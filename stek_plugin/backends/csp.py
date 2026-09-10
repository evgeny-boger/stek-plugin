"""CryptoPro CSP backend.

No cryptographic primitive is implemented here.  Every operation is
delegated to CryptoPro's certified `cryptcp` / `certmgr` executables, the
same provider the original Debian package depends on (lsb-cprocsp-kc1-64).

Command syntax verified against CryptCP 5.0 / Certmgr 1.1 (CSP 5.0 R2,
2021) on Linux:

    cryptcp -sign -thumbprint <hex> -nochain -der -detached <in> <out>
    cryptcp -sign -thumbprint <hex> -nochain -der -attached <in> <out>
    cryptcp -decr [-thumbprint <hex>] -nochain <in> <out>
    certmgr -list -store uMy
    certmgr -export -store uMy -thumbprint <hex> -dest <file>   (DER)

`cryptcp` has no serial-number selector, so CertSN is resolved to a
thumbprint through the certificate list first.  `-nochain` mirrors the
original, which calls CryptSignMessage without chain validation.
"""
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .base import (Certificate, CryptoBackend, is_thumbprint, normalize_serial,
                   serials_equal)
from .. import (OID_INN, OID_INNLE, OID_NAMES, QUALIFIED_SUBJECT_OIDS, TASK_ATTACHED_SIGN,
                TASK_BUILD_POVED, TASK_BUILD_SEDO, TASK_DECRYPT,
                TASK_DECRYPT_FSS, TASK_DECRYPT_SEDO, TASK_DETACHED_SIGN,
                TASK_SIGN_HASH, TASK_XMLDSIGN)

CSP_TIMEOUT = 600  # seconds; a PIN dialog left unanswered must not hang forever
LIST_CACHE_TTL = 5.0
log = logging.getLogger("stek_plugin")
# certmgr localises field names; pin the locale so the parser sees English.
TOOL_ENV = {**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}


class CSPError(RuntimeError):
    pass


def _find_tool(name):
    candidates = [
        shutil.which(name),
        f"/opt/cprocsp/bin/amd64/{name}",
        f"/opt/cprocsp/bin/{name}",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


# ---------------------------------------------------------------------------
# certmgr -list parser
# ---------------------------------------------------------------------------
_BLOCK_SPLIT = re.compile(r"(?m)^\s*\d+-{3,}\s*$")
_FIELD = re.compile(r"(?m)^([A-Za-z][A-Za-z0-9 ]*?)\s*:\s*(.*?)\s*$")


def parse_certmgr_list(text):
    """Split `certmgr -list` output into dicts of its 'Key : value' lines.

    Blocks are separated by lines like `1-------`.  Only the fields the
    backend needs are guaranteed: 'SHA1 Thumbprint', 'Serial',
    'PrivateKey Link'.
    """
    entries = []
    for block in _BLOCK_SPLIT.split(text)[1:]:
        fields = {}
        for key, value in _FIELD.findall(block):
            fields.setdefault(key.strip(), value)
        if fields.get("SHA1 Thumbprint"):
            entries.append(fields)
    return entries


def _extract_error(output):
    text = output.decode("utf-8", "replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    code = next((ln for ln in reversed(lines) if ln.startswith("[ErrorCode:")), "")
    detail = next((ln for ln in lines if ln.startswith(("Error", "Ошибка"))), "")
    if not detail:
        detail = next((ln for ln in reversed(lines)
                       if not ln.startswith("[ErrorCode:") and "(c)" not in ln
                       and not ln.startswith("Command prompt")), "")
    return " ".join(x for x in (detail, code) if x)


# ---------------------------------------------------------------------------
# X.509 name formatting (CryptoAPI CertNameToStr style, reversed RDN order)
# ---------------------------------------------------------------------------
def rdn_pairs(name):
    # CryptoAPI CertNameToStr order, confirmed byte-for-byte against the
    # original's ENUMCERTS output: the native DER order (Subject OGRNIP..SN,
    # Issuer INNLE..CN), NOT reversed.
    pairs = []
    for attr in name:
        key = OID_NAMES.get(attr.oid.dotted_string, "OID." + attr.oid.dotted_string)
        pairs.append((key, str(attr.value)))
    return pairs


def format_name(name):
    parts = []
    for key, value in rdn_pairs(name):   # no quoting, as observed on the original
        parts.append(f"{key}={value}")
    return ", ".join(parts)


def rdn_value(name, *keys):
    for key, value in rdn_pairs(name):
        if key in keys:
            return value
    return ""


def certificate_from_der(der, has_private_key=True):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    parsed = (x509.load_pem_x509_certificate(der) if der.startswith(b"-----BEGIN")
              else x509.load_der_x509_certificate(der))
    subject, issuer = parsed.subject, parsed.issuer
    serial = f"{parsed.serial_number:x}"
    if len(serial) % 2:
        serial = "0" + serial
    fio = " ".join(filter(None, [rdn_value(subject, "SN"), rdn_value(subject, "G", "GN")]))
    # The original formats validity with the local TDateTime, not UTC.
    valid_from = parsed.not_valid_before_utc.astimezone()
    valid_to = parsed.not_valid_after_utc.astimezone()
    return Certificate(
        serial_hex=serial,
        thumbprint=parsed.fingerprint(hashes.SHA1()).hex(),
        subject_full=format_name(subject),
        subject_name=rdn_value(subject, "O") or rdn_value(subject, "CN"),
        issuer_full=format_name(issuer),
        issuer_name=rdn_value(issuer, "CN"),
        subject_fio=fio,
        valid_from=valid_from,
        valid_to=valid_to,
        der=der,
        has_private_key=has_private_key,
        inn=rdn_value(subject, "INNLE") or rdn_value(subject, "INN"),
        qualified=any(a.oid.dotted_string in QUALIFIED_SUBJECT_OIDS for a in subject),
    )


class CryptoProBackend(CryptoBackend):
    def __init__(self, cryptcp=None, certmgr=None, store="uMy", pin=None):
        self.cryptcp = cryptcp or _find_tool("cryptcp")
        self.certmgr = certmgr or _find_tool("certmgr")
        self.store = store
        self.pin = pin if pin is not None else os.environ.get("STEK_CSP_PIN")
        if not self.cryptcp or not self.certmgr:
            raise CSPError(
                "CryptoPro CSP tools not found; install lsb-cprocsp-kc1-64 "
                "and the cryptcp/certmgr packages")
        # One CSP operation at a time: two cryptcp processes on the same
        # token would raise two PIN dialogs.
        self._lock = threading.RLock()
        self._list_cache = (0.0, [])
        self._der_cache = {}

    # -- process helpers ---------------------------------------------------
    def _run(self, args, timeout=CSP_TIMEOUT):
        try:
            proc = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                                  check=False, timeout=timeout, env=TOOL_ENV)
        except subprocess.TimeoutExpired:
            raise CSPError(f"{os.path.basename(args[0])} timed out after {timeout}s "
                           "(PIN prompt not answered?)")
        if proc.returncode:
            raise CSPError(_extract_error(proc.stdout + proc.stderr)
                           or f"{os.path.basename(args[0])} failed ({proc.returncode})")
        return proc.stdout

    def _selector(self, task):
        if task.cert_thumb:
            if not is_thumbprint(task.cert_thumb):
                raise CSPError(f"сертификат с отпечатком: {task.cert_thumb} не найден")
            return ["-thumbprint", normalize_serial(task.cert_thumb)]
        if task.cert_sn:
            cert = self.certificate(serial=task.cert_sn)
            if cert is None:
                raise CSPError(f"сертификат с SN: {task.cert_sn} не найден")
            return ["-thumbprint", cert.thumbprint]
        return []

    def _pin_args(self):
        return ["-pin", self.pin] if self.pin else []

    # -- CryptoBackend -----------------------------------------------------
    def execute_task(self, task):
        with self._lock:
            return self._execute(task)

    def _execute(self, task):
        with tempfile.TemporaryDirectory(prefix="stek-csp-") as td:
            src = Path(td) / "input.bin"
            dst = Path(td) / "output.bin"
            src.write_bytes(task.in_data)
            if task.ttype in (TASK_DETACHED_SIGN, TASK_ATTACHED_SIGN,
                              TASK_BUILD_POVED, TASK_BUILD_SEDO):
                selector = self._selector(task)
                if not selector:
                    raise CSPError("Certificate serial/thumbprint is required")
                mode = "-attached" if task.ttype == TASK_ATTACHED_SIGN else "-detached"
                args = [self.cryptcp, "-sign", *selector, "-nochain", "-der",
                        mode, *self._pin_args(), str(src), str(dst)]
            elif task.ttype in (TASK_DECRYPT, TASK_DECRYPT_FSS, TASK_DECRYPT_SEDO):
                args = [self.cryptcp, "-decr", *self._selector(task), "-nochain",
                        *self._pin_args(), str(src), str(dst)]
            elif task.ttype == TASK_SIGN_HASH:
                raise CSPError(
                    "SIGN_HASH (CryptSignHash over a precomputed digest) is not "
                    "exposed by cryptcp; it needs the CryptoPro pycades module "
                    "or a CryptoAPI adapter")
            elif task.ttype == TASK_XMLDSIGN:
                raise CSPError(
                    "GET_XML_SIGN requires a CryptoPro-enabled XML-DSig library "
                    "(e.g. xmlsec built against the CSP); not available")
            else:
                raise CSPError(f"Unsupported crypto task type {task.ttype}")
            self._run(args)
            if not dst.exists():
                raise CSPError("CryptoPro did not produce an output file")
            return dst.read_bytes()

    def list_store(self):
        stamp, cached = self._list_cache
        if time.monotonic() - stamp < LIST_CACHE_TTL:
            return cached
        output = self._run([self.certmgr, "-list", "-store", self.store])
        text = output.decode("utf-8", "replace")
        entries = parse_certmgr_list(text)
        if not entries and "Thumbprint" not in text and "-------" in text:
            log.warning("certmgr -list output not understood (locale?): %r", text[:200])
        self._list_cache = (time.monotonic(), entries)
        return entries

    def certificates(self, only_private=True, inn="", only_valid=False,
                     qualified_only=True):
        certs = []
        now = datetime.now(timezone.utc)
        with self._lock:
            for entry in self.list_store():
                private = entry.get("PrivateKey Link", "").strip().lower().startswith("yes")
                if only_private and not private:
                    continue
                thumb = normalize_serial(entry["SHA1 Thumbprint"])
                if not is_thumbprint(thumb):
                    continue
                cert = certificate_from_der(self._export(thumb), private)
                cert.thumbprint = thumb        # the store key certmgr exported by
                if entry.get("Serial"):
                    cert.serial_hex = normalize_serial(entry["Serial"])
                if qualified_only and not cert.qualified:
                    continue
                if inn and cert.inn != inn:
                    continue
                if only_valid and not cert.valid_from <= now <= cert.valid_to:
                    continue
                certs.append(cert)
        return certs

    def _export(self, thumbprint):
        der = self._der_cache.get(thumbprint)
        if der is None:
            with tempfile.TemporaryDirectory(prefix="stek-cert-") as td:
                dst = Path(td) / "cert.cer"
                self._run([self.certmgr, "-export", "-store", self.store,
                           "-thumbprint", thumbprint, "-dest", str(dst)])
                der = dst.read_bytes()
            self._der_cache[thumbprint] = der
        return der
