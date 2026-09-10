"""CryptoPro CSP backend through the official `pycades` Python module
(CryptoPro CAdES SDK, https://docs.cryptopro.ru/cades/pycades).

Everything cryptographic happens inside libcppcades/libcades/the CSP; this
file only marshals bytes.  Compared with the `cryptcp` adapter it needs no
temporary files or subprocesses and exposes `RawSignature.SignHash`, the
CryptSignHash equivalent the original plugin uses for `SIGN_HASH`.

pycades is not on PyPI: build it from CryptoPro's pycades.zip against the
CSP headers (see tools/pycades/ and README).  The module is imported lazily
so that the cryptcp backend and the unit tests never load the CSP.

Caveats vs. the original binary:
- `SignCades(CADESCOM_PKCS7_TYPE)` yields a CAPICOM-style SignedData (with
  signed attributes such as signingTime); `CryptSignMessage` output is not
  byte-identical, but consumers verify either.
- `RawSignature.SignHash` returns the signature in the same byte order as
  `CryptSignHash` (verified live: a `csptest -keyset -sign` signature
  passes `RawSignature.VerifyHash` unreversed), so the hex is returned
  as-is, matching the original's raw CryptSignHashA output.
- Calls run in-process without a timeout: an unanswered CSP PIN dialog
  blocks the backend.  Supply the PIN or use the cryptcp backend.
"""
import base64
import binascii
import os
import threading
from datetime import datetime, timezone

from .base import CryptoBackend, normalize_serial, serials_equal
from .csp import CSPError, certificate_from_der
from .. import (OID_GOST3410_2001, OID_GOST3410_2012_256, OID_GOST3410_2012_512,
                TASK_ATTACHED_SIGN, TASK_BUILD_POVED, TASK_BUILD_SEDO, TASK_DECRYPT,
                TASK_DECRYPT_FSS, TASK_DECRYPT_SEDO, TASK_DETACHED_SIGN,
                TASK_SIGN_HASH, TASK_XMLDSIGN)

# Verified 2026-08-25 against csptest -keyset -sign: RawSignature uses the
# CryptSignHash byte order, no reversal needed.
RAW_SIGNATURE_REVERSED = False


# pycades.so has a RUNPATH for /opt/cprocsp/lib/amd64 but DT_RUNPATH does not
# cascade to its dependencies' own dependencies (libcppcades -> libcplib), so
# the plain import is fragile when those libraries are not in the loader
# cache.  Preload the CSP chain by full path with RTLD_GLOBAL first.
_CSP_LIBS = ("libcpalloc.so", "libcplib.so", "libcapi10.so", "libcapi20.so",
             "librdrsup.so", "libcades.so", "libcppcades.so")


def _preload_csp():
    import ctypes
    import glob
    for base in _CSP_LIBS:
        for lib_dir in ("/opt/cprocsp/lib/amd64", "/opt/cprocsp/lib"):
            hits = sorted(glob.glob(f"{lib_dir}/{base}*"))
            if hits:
                try:
                    ctypes.CDLL(hits[0], mode=ctypes.RTLD_GLOBAL)
                except OSError:
                    pass
                break


def _import():
    try:
        import pycades
        return pycades
    except ImportError:
        pass
    _preload_csp()
    try:
        import pycades
        return pycades
    except ImportError:
        return None


def is_available():
    return _import() is not None


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode("".join(str(text).split()))


class PycadesBackend(CryptoBackend):
    """CryptoBackend over pycades.  All calls are serialized with a lock:
    the CAdES COM-style objects are not documented as thread-safe."""

    def __init__(self, store_name=None, pin=None, module=None):
        self.api = module or _import()
        if self.api is None:
            raise CSPError("pycades module is not installed; see tools/pycades/")
        self.store_name = store_name or self.api.CAPICOM_MY_STORE
        self.pin = pin if pin is not None else os.environ.get("STEK_CSP_PIN")
        self._lock = threading.RLock()

    # -- store access ------------------------------------------------------
    def _store_certificates(self):
        """Materialized list, store closed deterministically."""
        store = self.api.Store()
        store.Open(self.api.CADESCOM_CURRENT_USER_STORE, self.store_name,
                   self.api.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED)
        try:
            certs = store.Certificates
            return [certs.Item(i) for i in range(1, certs.Count + 1)]
        finally:
            store.Close()

    def _find(self, serial="", thumbprint=""):
        thumbprint = normalize_serial(thumbprint)
        for cert in self._store_certificates():
            if thumbprint and cert.Thumbprint.lower() == thumbprint:
                return cert
            if serial and serials_equal(cert.SerialNumber, serial):
                return cert
        return None

    def _require(self, task):
        cert = self._find(task.cert_sn, task.cert_thumb)
        if cert is None:
            value = task.cert_thumb or task.cert_sn
            kind = "отпечатком" if task.cert_thumb else "SN"
            raise CSPError(f"сертификат с {kind}: {value} не найден")
        return cert

    def _apply_pin(self, cert):
        """CPPrivateKey.KeyPin (write-only) covers SignHash and Decrypt,
        which take no Signer."""
        if self.pin:
            cert.PrivateKey.KeyPin = self.pin

    # -- CryptoBackend -----------------------------------------------------
    def certificates(self, only_private=True, inn="", only_valid=False,
                     qualified_only=True):
        result = []
        now = datetime.now(timezone.utc)
        with self._lock:
            for raw in self._store_certificates():
                private = bool(raw.HasPrivateKey())
                if only_private and not private:
                    continue
                der = _unb64(raw.Export(self.api.CADESCOM_ENCODE_BASE64))
                cert = certificate_from_der(der, private)
                cert.serial_hex = normalize_serial(raw.SerialNumber)
                cert.thumbprint = raw.Thumbprint.lower()
                if qualified_only and not cert.qualified:
                    continue
                if inn and cert.inn != inn:
                    continue
                # Date check only, like the original (IsValid() would do
                # online chain/revocation checks).
                if only_valid and not cert.valid_from <= now <= cert.valid_to:
                    continue
                result.append(cert)
        return result

    def execute_task(self, task):
        with self._lock:
            try:
                return self._execute(task)
            except CSPError:
                raise
            except Exception as exc:  # pycades raises plain Exception with the CSP text
                raise CSPError(str(exc) or exc.__class__.__name__) from exc

    def _execute(self, task):
        if task.ttype in (TASK_DETACHED_SIGN, TASK_ATTACHED_SIGN,
                          TASK_BUILD_POVED, TASK_BUILD_SEDO):
            return self._sign(task, detached=task.ttype != TASK_ATTACHED_SIGN)
        if task.ttype == TASK_SIGN_HASH:
            return self._sign_hash(task)
        if task.ttype in (TASK_DECRYPT, TASK_DECRYPT_FSS, TASK_DECRYPT_SEDO):
            return self._decrypt(task)
        if task.ttype == TASK_XMLDSIGN:
            raise CSPError("GET_XML_SIGN: the proprietary XML envelope is not "
                           "reconstructed; pycades.SignedXML is available once it is")
        raise CSPError(f"Unsupported crypto task type {task.ttype}")

    def _signer(self, cert):
        signer = self.api.Signer()
        signer.Certificate = cert
        signer.CheckCertificate = False           # CryptSignMessage does no chain check
        # The original embeds only the signer certificate (CryptSignMessage
        # default), not the chain.
        signer.Options = self.api.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY
        if self.pin:
            signer.KeyPin = self.pin
        return signer

    def _sign(self, task, detached):
        cert = self._require(task)
        signed = self.api.SignedData()
        signed.ContentEncoding = self.api.CADESCOM_BASE64_TO_BINARY   # before Content
        signed.Content = _b64(task.in_data)
        # Plain PKCS#7/CMS SignedData (CADESCOM_PKCS7_TYPE), like CryptSignMessage.
        result = signed.SignCades(self._signer(cert), self.api.CADESCOM_PKCS7_TYPE,
                                  detached, self.api.CADESCOM_ENCODE_BASE64)
        return _unb64(result)

    def _hash_algorithm(self, cert, digest):
        """Pick the GOST R 34.11 variant from the key algorithm; a 32-byte
        digest is ambiguous between 34.11-94 (2001 keys) and 34.11-2012-256."""
        key_oid = cert.PublicKey().Algorithm.Value
        table = {
            OID_GOST3410_2001: (32, self.api.CADESCOM_HASH_ALGORITHM_CP_GOST_3411),
            OID_GOST3410_2012_256: (32, self.api.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256),
            OID_GOST3410_2012_512: (64, self.api.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512),
        }
        if key_oid not in table:
            raise CSPError(f"SIGN_HASH: unsupported key algorithm {key_oid}")
        size, algorithm = table[key_oid]
        if len(digest) != size:
            raise CSPError(f"SIGN_HASH expects a {size}-byte digest for key "
                           f"algorithm {key_oid}, got {len(digest)} bytes")
        return algorithm

    def _sign_hash(self, task):
        # The original passes the Base64-decoded body straight to CryptSignHashA.
        cert = self._require(task)
        self._apply_pin(cert)
        hashed = self.api.HashedData()
        hashed.Algorithm = self._hash_algorithm(cert, task.in_data)   # before SetHashValue
        hashed.SetHashValue(task.in_data.hex())
        signature = binascii.unhexlify(self.api.RawSignature().SignHash(hashed, cert))
        return signature[::-1] if RAW_SIGNATURE_REVERSED else signature

    def _decrypt(self, task):
        if task.cert_thumb or task.cert_sn:
            self._apply_pin(self._require(task))
        elif self.pin:
            for cert in self._store_certificates():
                if cert.HasPrivateKey():
                    self._apply_pin(cert)
        enveloped = self.api.EnvelopedData()
        enveloped.ContentEncoding = self.api.CADESCOM_BASE64_TO_BINARY
        enveloped.Decrypt(_b64(task.in_data))
        return _unb64(enveloped.Content)
