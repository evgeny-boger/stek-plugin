"""CryptoPro adapter tests that need no CSP: certmgr output parsing and
X.509 name formatting via `cryptography`."""
import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from stek_plugin import OID_INN, OID_OGRNIP, OID_SNILS
from stek_plugin.backends.base import normalize_serial, serials_equal
from stek_plugin.backends.csp import (CryptoProBackend, _extract_error,
                                      certificate_from_der, parse_certmgr_list)
from stek_plugin.taskdb import Task
from stek_plugin import TASK_ATTACHED_SIGN, TASK_DECRYPT, TASK_DETACHED_SIGN

CERTMGR_OUTPUT = """\
Certmgr 1.1 (c) "Crypto-Pro", 2007-2021.
Program for managing certificates, CRLs and stores.
=============================================================================
1-------
Issuer              : E=ca@example.org, O=Test CA, CN=Test CA
Subject             : OGRNIP=300000000000001, SNILS=00000000000, INN=000000000000, C=RU, S=77 г Москва, L=г Москва, CN=Тестов Тест Тестович, G=Тест Тестович, SN=Тестов
Serial              : 0x0123456789ABCDEF0123456789ABCDEF01
SHA1 Thumbprint     : 0123456789abcdef0123456789abcdef01234567
SubjKeyID           : 4297133f9c2d0ce14b612f472faf8c2eb80bcef1
Signature Algorithm : ГОСТ Р 34.11-2012/34.10-2012 256 бит
PublicKey Algorithm : ГОСТ Р 34.10-2012 256 бит (512 bits)
Not valid before    : 13/07/2026  19:19:12 UTC
Not valid after     : 13/10/2027  19:29:12 UTC
Embedded License    : CryptoPro CSP
PrivateKey Link     : Yes                 
Container           : SCARD\\rutoken_lt_0\\0A00\\0000
Provider Name       : Crypto-Pro GOST R 34.10-2012 KC1 CSP
Extended Key Usage  : 1.3.6.1.5.5.7.3.2 Проверка подлинности клиента
                      1.3.6.1.5.5.7.3.4 Защищенная электронная почта
2-------
Issuer              : CN=Other CA
Subject             : CN=No key
Serial              : 0x02
SHA1 Thumbprint     : ffffffffffffffffffffffffffffffffffffffff
PrivateKey Link     : No
=============================================================================

[ErrorCode: 0x00000000]
"""


class CertmgrParserTest(unittest.TestCase):
    def test_blocks_and_fields(self):
        entries = parse_certmgr_list(CERTMGR_OUTPUT)
        self.assertEqual(len(entries), 2)
        first, second = entries
        self.assertEqual(first["SHA1 Thumbprint"], "0123456789abcdef0123456789abcdef01234567")
        self.assertEqual(first["Serial"], "0x0123456789ABCDEF0123456789ABCDEF01")
        self.assertEqual(first["PrivateKey Link"], "Yes")
        self.assertEqual(second["PrivateKey Link"], "No")
        self.assertIn("SN=Тестов", first["Subject"])

    def test_serial_normalization(self):
        self.assertEqual(normalize_serial("0x0123:45 ab"), "012345ab")
        self.assertTrue(serials_equal("0x0123AB", "123ab"))
        self.assertFalse(serials_equal("0x0123AB", "123ac"))

    def test_error_extraction(self):
        out = (b'CryptCP 5.0 (c) "Crypto-Pro", 2002-2021.\n'
               b"Command prompt Utility for file signature and encryption.\n\n"
               b"Error: Too many commands: ''.\n"
               b"../../../../CSPbuild/CSP/samples/CPCrypt/Params.cpp:297: 0x200000CA\n"
               b"[ErrorCode: 0x200000ca]\n")
        self.assertEqual(_extract_error(out),
                         "Error: Too many commands: ''. [ErrorCode: 0x200000ca]")


def make_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    # real certificates are encoded OGRNIP-first / streetAddress-first; the
    # plugin prints them in that (native DER) order.
    subject = x509.Name([
        x509.NameAttribute(ObjectIdentifier(OID_OGRNIP), "300000000000001"),
        x509.NameAttribute(ObjectIdentifier(OID_SNILS), "00000000000"),
        x509.NameAttribute(ObjectIdentifier(OID_INN), "000000000000"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "77 г Москва"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "г Москва"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Тестов Тест Тестович"),
        x509.NameAttribute(NameOID.GIVEN_NAME, "Тест Тестович"),
        x509.NameAttribute(NameOID.SURNAME, "Тестов"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.STREET_ADDRESS, "ул. Тестовая, д. 1"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(0x0123456789abcdef)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    from cryptography.hazmat.primitives.serialization import Encoding
    return cert.public_bytes(Encoding.DER)


class FakeProc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, b"", returncode


class CryptcpArgvTest(unittest.TestCase):
    """Assert the exact command lines without running CryptoPro."""

    def setUp(self):
        self.calls = []
        self.backend = CryptoProBackend(cryptcp="/x/cryptcp", certmgr="/x/certmgr", pin="0000")

        def fake_run(args, **kw):
            self.calls.append(list(args))
            if args[1] == "-list":
                return FakeProc(CERTMGR_OUTPUT.encode())
            if args[1] == "-export":
                with open(args[args.index("-dest") + 1], "wb") as fh:
                    fh.write(make_cert())
            elif args[1] in ("-sign", "-decr"):
                with open(args[-1], "wb") as fh:
                    fh.write(b"OUT")
            return FakeProc()
        import subprocess
        self._orig, subprocess.run = subprocess.run, fake_run

    def tearDown(self):
        import subprocess
        subprocess.run = self._orig

    def test_sign_by_thumbprint(self):
        task = Task(id="t", ttype=TASK_DETACHED_SIGN, cert_thumb="AB" * 20, in_data=b"d")
        self.assertEqual(self.backend.execute_task(task), b"OUT")
        args = self.calls[-1]
        self.assertEqual(args[:8], ["/x/cryptcp", "-sign", "-thumbprint", "ab" * 20,
                                    "-nochain", "-der", "-detached", "-pin"])
        self.assertEqual(args[8], "0000")
        task.ttype = TASK_ATTACHED_SIGN
        self.backend.execute_task(task)
        self.assertIn("-attached", self.calls[-1])

    def test_sign_by_serial_resolves_thumbprint(self):
        task = Task(id="t", ttype=TASK_DETACHED_SIGN, cert_sn="0x0123456789ABCDEF0123456789ABCDEF01",
                    in_data=b"d")
        self.backend.execute_task(task)
        self.assertEqual(self.calls[0][:2], ["/x/certmgr", "-list"])
        self.assertEqual(self.calls[-1][2:4], ["-thumbprint", "0123456789abcdef0123456789abcdef01234567"])

    def test_bad_thumbprint_never_reaches_argv(self):
        task = Task(id="t", ttype=TASK_DETACHED_SIGN, cert_thumb="-dn", in_data=b"d")
        with self.assertRaises(Exception):
            self.backend.execute_task(task)
        self.assertEqual(self.calls, [])

    def test_decrypt_without_selector_and_no_pin(self):
        self.backend.pin = None
        task = Task(id="t", ttype=TASK_DECRYPT, in_data=b"enc")
        self.backend.execute_task(task)
        self.assertEqual(self.calls[-1][:3], ["/x/cryptcp", "-decr", "-nochain"])
        self.assertNotIn("-pin", self.calls[-1])


class NameFormattingTest(unittest.TestCase):
    def test_certmgr_style_subject(self):
        cert = certificate_from_der(make_cert())
        self.assertEqual(cert.subject_full,
                         "OGRNIP=300000000000001, SNILS=00000000000, INN=000000000000, "
                         "C=RU, S=77 г Москва, L=г Москва, CN=Тестов Тест Тестович, "
                         "GN=Тест Тестович, SN=Тестов")
        self.assertEqual(cert.issuer_full, 'streetAddress=ул. Тестовая, д. 1, O=Test CA, CN=Test CA')
        self.assertEqual(cert.subject_name, "Тестов Тест Тестович")
        self.assertEqual(cert.issuer_name, "Test CA")
        self.assertEqual(cert.subject_fio, "Тестов Тест Тестович")
        self.assertEqual(cert.serial_hex, "0123456789abcdef")
        self.assertEqual(cert.inn, "000000000000")
        self.assertEqual(cert.valid_from.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d"),
                         "2026-01-01")
        self.assertEqual(len(cert.thumbprint), 40)


if __name__ == "__main__":
    unittest.main()
