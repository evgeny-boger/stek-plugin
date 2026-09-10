"""PycadesBackend marshalling tests against a strict fake `pycades` module
(no CSP), plus an opt-in live enumeration test."""
import base64
import os
import unittest

from stek_plugin import (OID_GOST3410_2001, OID_GOST3410_2012_256,
                         OID_GOST3410_2012_512, TASK_ATTACHED_SIGN, TASK_DECRYPT,
                         TASK_DETACHED_SIGN, TASK_SIGN_HASH)
from stek_plugin.backends.csp import CSPError
from stek_plugin.backends.pycades_backend import PycadesBackend, is_available
from stek_plugin.taskdb import Task
from tests.test_csp_backend import make_cert

DER = make_cert()
THUMB = "0123456789abcdef0123456789abcdef01234567"
LOG = []   # (object, attribute, value) in the order the backend sets them


class Strict:
    """Only the documented CAdESCOM properties may be assigned."""
    _allowed = ()

    def __setattr__(self, name, value):
        if name not in self._allowed:
            raise AttributeError(f"{type(self).__name__} has no property {name}")
        LOG.append((type(self).__name__, name, value))
        object.__setattr__(self, name, value)


class FakeAlgorithm:
    Value = OID_GOST3410_2012_256


class FakePublicKey:
    Algorithm = FakeAlgorithm()


class FakePrivateKey(Strict):
    _allowed = ("KeyPin",)


class FakeCert:
    Thumbprint = THUMB.upper()
    SerialNumber = "0123456789ABCDEF"

    def __init__(self):
        self.PrivateKey = FakePrivateKey()

    def HasPrivateKey(self): return True
    def Export(self, encoding): return base64.b64encode(DER).decode()
    def PublicKey(self): return FakePublicKey()


CERT = FakeCert()


class FakeCerts:
    Count = 1
    def Item(self, i): return CERT


class FakeStore(Strict):
    _allowed = ("opened", "closed")
    Certificates = FakeCerts()
    def Open(self, *a): self.opened = a; FakeStore.last = self
    def Close(self): self.closed = True


class FakeSigner(Strict):
    _allowed = ("Certificate", "CheckCertificate", "Options", "KeyPin")


class FakeSignedData(Strict):
    _allowed = ("ContentEncoding", "Content")
    calls = []

    def SignCades(self, signer, cades_type, detached, encoding):
        FakeSignedData.calls.append((signer, cades_type, detached, encoding, self.Content))
        return base64.b64encode(b"cms:" + base64.b64decode(self.Content)).decode()


class FakeHashed(Strict):
    _allowed = ("Algorithm", "DataEncoding")
    def SetHashValue(self, value): LOG.append(("FakeHashed", "SetHashValue", value))


class FakeRaw:
    def SignHash(self, hashed, cert):
        assert isinstance(hashed, FakeHashed) and isinstance(cert, FakeCert)
        value = dict((n, v) for _, n, v in LOG if _ == "FakeHashed")
        return ("%02x" % value["Algorithm"]) + value["SetHashValue"]


class FakeEnveloped(Strict):
    _allowed = ("ContentEncoding", "Content")
    def Decrypt(self, content):
        self.Content = base64.b64encode(b"plain:" + base64.b64decode(content)).decode()


class FakePycades:
    CAPICOM_MY_STORE = "My"
    CADESCOM_CURRENT_USER_STORE = 2
    CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2
    CADESCOM_ENCODE_BASE64 = 0
    CADESCOM_BASE64_TO_BINARY = 1
    CADESCOM_PKCS7_TYPE = 65535
    CADESCOM_HASH_ALGORITHM_CP_GOST_3411 = 100
    CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256 = 101
    CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512 = 102
    CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY = 2
    Store = FakeStore
    Signer = FakeSigner
    SignedData = FakeSignedData
    HashedData = FakeHashed
    RawSignature = FakeRaw
    EnvelopedData = FakeEnveloped


def names(cls):
    return [n for c, n, _ in LOG if c == cls]


class PycadesBackendTest(unittest.TestCase):
    def setUp(self):
        self.backend = PycadesBackend(module=FakePycades(), pin="1234")
        FakeSignedData.calls.clear()
        LOG.clear()
        FakeAlgorithm.Value = OID_GOST3410_2012_256

    def test_certificates(self):
        certs = self.backend.certificates(only_valid=True)
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0].thumbprint, THUMB)
        self.assertEqual(certs[0].serial_hex, "0123456789abcdef")
        self.assertEqual(certs[0].subject_fio, "Тестов Тест Тестович")
        self.assertEqual(FakeStore.last.opened, (2, "My", 2))
        self.assertTrue(FakeStore.last.closed)
        self.assertIsNotNone(self.backend.certificate(serial="123456789ABCDEF"))

    def test_sign_detached_plain_pkcs7(self):
        task = Task(id="t", ttype=TASK_DETACHED_SIGN, cert_thumb=THUMB, in_data=b"doc")
        self.assertEqual(self.backend.execute_task(task), b"cms:doc")
        signer, cades_type, detached, encoding, content = FakeSignedData.calls[0]
        self.assertEqual((cades_type, detached, encoding), (65535, True, 0))
        self.assertEqual(base64.b64decode(content), b"doc")
        self.assertIs(signer.Certificate, CERT)
        self.assertIs(signer.CheckCertificate, False)
        self.assertEqual((signer.Options, signer.KeyPin), (2, "1234"))
        self.assertEqual(names("FakeSignedData"), ["ContentEncoding", "Content"])
        task.ttype = TASK_ATTACHED_SIGN
        self.backend.execute_task(task)
        self.assertIs(FakeSignedData.calls[1][2], False)

    def test_no_pin_leaves_keypin_unset(self):
        self.backend.pin = None
        task = Task(id="t", ttype=TASK_DETACHED_SIGN, cert_thumb=THUMB, in_data=b"doc")
        self.backend.execute_task(task)
        self.assertNotIn("KeyPin", names("FakeSigner"))

    def test_unknown_certificate(self):
        task = Task(id="t", ttype=TASK_DETACHED_SIGN, cert_thumb="f" * 40, in_data=b"doc")
        with self.assertRaises(CSPError) as ctx:
            self.backend.execute_task(task)
        self.assertIn("не найден", str(ctx.exception))

    def test_sign_hash_and_pin_on_key(self):
        raw = bytes(range(32))
        task = Task(id="t", ttype=TASK_SIGN_HASH, cert_sn="0123456789abcdef", in_data=raw)
        self.assertEqual(self.backend.execute_task(task), bytes([101]) + raw)
        self.assertEqual(names("FakeHashed"), ["Algorithm", "SetHashValue"])
        self.assertIn(("FakePrivateKey", "KeyPin", "1234"), LOG)

    def test_sign_hash_algorithm_from_key(self):
        task = Task(id="t", ttype=TASK_SIGN_HASH, cert_sn="0123456789abcdef", in_data=bytes(64))
        with self.assertRaises(CSPError):        # 64-byte digest for a 256-bit key
            self.backend.execute_task(task)
        FakeAlgorithm.Value = OID_GOST3410_2012_512
        self.assertEqual(self.backend.execute_task(task)[0], 102)
        FakeAlgorithm.Value = OID_GOST3410_2001
        task.in_data = bytes(32)
        self.assertEqual(self.backend.execute_task(task)[0], 100)
        FakeAlgorithm.Value = "1.2.840.113549.1.1.1"
        with self.assertRaises(CSPError):
            self.backend.execute_task(task)

    def test_decrypt(self):
        task = Task(id="t", ttype=TASK_DECRYPT, in_data=b"enc")
        self.assertEqual(self.backend.execute_task(task), b"plain:enc")
        self.assertIn(("FakePrivateKey", "KeyPin", "1234"), LOG)   # applied to store keys
        self.assertEqual(names("FakeEnveloped")[0], "ContentEncoding")
        LOG.clear()
        task.cert_thumb = "f" * 40
        with self.assertRaises(CSPError):
            self.backend.execute_task(task)

    def test_module_exception_becomes_csperror(self):
        def boom(*a, **k): raise Exception("0x8010006b: Wrong PIN")
        original, FakeSignedData.SignCades = FakeSignedData.SignCades, boom
        try:
            task = Task(id="t", ttype=TASK_DETACHED_SIGN, cert_thumb=THUMB, in_data=b"doc")
            with self.assertRaises(CSPError) as ctx:
                self.backend.execute_task(task)
            self.assertIn("Wrong PIN", str(ctx.exception))
        finally:
            FakeSignedData.SignCades = original


@unittest.skipUnless(os.environ.get("STEK_LIVE") and is_available(), "set STEK_LIVE=1 with pycades installed")
class LivePycadesTest(unittest.TestCase):
    def test_enumerate(self):
        backend = PycadesBackend()
        certs = backend.certificates(only_private=False)
        for cert in certs:
            self.assertRegex(cert.thumbprint, r"^[0-9a-f]{40}$")
            self.assertTrue(cert.der.startswith(b"\x30"))
        self.assertTrue(backend.certificates(only_valid=True) or not certs)


if __name__ == "__main__":
    unittest.main()
