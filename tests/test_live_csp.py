"""Live tests against an installed CryptoPro CSP.

Opt-in: skipped unless STEK_LIVE=1 and cryptcp/certmgr are present.
Signing uses the CryptoPro test certificate CN=mykey (software container,
thumbprint 10bd0d35...) unless STEK_LIVE_SIGN overrides it.  Signing is skipped unless
STEK_LIVE_SIGN=<thumbprint> is set, because it needs the key container PIN
(pass it via STEK_CSP_PIN or answer the CSP dialog).
"""
import os
import unittest

from stek_plugin import TASK_ATTACHED_SIGN, TASK_DETACHED_SIGN
from stek_plugin.backends.csp import CryptoProBackend, CSPError, _find_tool
from stek_plugin.taskdb import Task

TEST_THUMB = "10bd0d35317f260ada2380e93541489c6a98f77f"   # CN=mykey, E=test@cryptopro.ru


@unittest.skipUnless(os.environ.get("STEK_LIVE") and _find_tool("cryptcp") and _find_tool("certmgr"),
                     "set STEK_LIVE=1 with CryptoPro CSP installed")
class LiveCspTest(unittest.TestCase):
    def setUp(self):
        self.backend = CryptoProBackend()

    def test_enumerate_store(self):
        certs = self.backend.certificates(only_private=False)
        for cert in certs:
            self.assertRegex(cert.thumbprint, r"^[0-9a-f]{40}$")
            self.assertRegex(cert.serial_hex, r"^[0-9a-f]+$")
            self.assertTrue(cert.der.startswith(b"\x30"))
            self.assertIn("CN=", cert.subject_full)
        if certs:
            found = self.backend.certificate(thumbprint=certs[0].thumbprint.upper())
            self.assertEqual(found.serial_hex, certs[0].serial_hex)
            found = self.backend.certificate(serial="0x" + certs[0].serial_hex.upper())
            self.assertEqual(found.thumbprint, certs[0].thumbprint)

    def test_sign(self):
        thumb = os.environ.get("STEK_LIVE_SIGN", TEST_THUMB).lower()
        if self.backend.certificate(thumbprint=thumb) is None:
            self.skipTest(f"test certificate {thumb} not in store")
        for ttype in (TASK_DETACHED_SIGN, TASK_ATTACHED_SIGN):
            task = Task(id="live", ttype=ttype, cert_thumb=thumb, in_data=b"stek live test\n")
            cms = self.backend.execute_task(task)
            # DER SEQUENCE wrapping pkcs7-signedData (1.2.840.113549.1.7.2)
            self.assertEqual(cms[0], 0x30)
            self.assertIn(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02", cms[:32])


if __name__ == "__main__":
    unittest.main()
