import base64
import json
import re
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

from stek_plugin import (MSG_BAD_FSS_NUM, MSG_IN_PROGRESS, MSG_NO_FSS_NUM,
                         MSG_NO_SN, MSG_NO_SN_DEC, MSG_NO_SN_ESK, MSG_NO_SN_SIGN,
                         MSG_NO_TASKID, VERSION)
from stek_plugin.backends.base import Certificate, CryptoBackend
from stek_plugin.params import Params
from stek_plugin.server import Plugin, decode_document
from stek_plugin.taskdb import new_task_id


class FakeBackend(CryptoBackend):
    """Protocol-only fixture. It deliberately performs no cryptography."""
    def __init__(self):
        self.gate = threading.Event()
        self.gate.set()

    def execute_task(self, task):
        self.gate.wait(5)
        if task.in_data == b"fail":
            raise RuntimeError("boom")
        return b"result:" + task.in_data

    def certificates(self, only_private=True, inn="", only_valid=False, qualified_only=True):
        now = datetime.now(timezone.utc)
        certs = [Certificate("01ab", "a" * 40, "CN=Test", "Test", "CN=CA", "CA",
                             "Ivanov Ivan", now - timedelta(days=1),
                             now + timedelta(days=1), b"certificate", True, "7701"),
                 Certificate("02cd", "b" * 40, "CN=NoKey", "NoKey", "CN=CA", "CA",
                             "", now - timedelta(days=1), now + timedelta(days=1),
                             b"cert2", False, ""),
                 Certificate("03ef", "c" * 40, "CN=Expired", "Expired", "CN=CA", "CA",
                             "", now - timedelta(days=9), now - timedelta(days=1),
                             b"cert3", True, ""),
                 # qualified=False: a valid, keyed, but non-INN cert (like CN=mykey)
                 Certificate("04ff", "d" * 40, "CN=NoInn", "NoInn", "CN=CA", "CA",
                             "", now - timedelta(days=1), now + timedelta(days=1),
                             b"cert4", True, "", qualified=False)]
        if only_private:
            certs = [c for c in certs if c.has_private_key]
        if qualified_only:
            certs = [c for c in certs if c.qualified]
        if inn:
            certs = [c for c in certs if c.inn == inn]
        if only_valid:
            certs = [c for c in certs if c.valid_from <= now <= c.valid_to]
        return certs

    # A real DER whose SHA-1 the POST CHECKCERTANDCLUE path will compute.
    real_der = None
    real_thumb = None
    real_has_key = True

    def certificate(self, serial="", thumbprint=""):
        if self.real_thumb and thumbprint.lower() == self.real_thumb:
            from stek_plugin.backends.base import Certificate
            return Certificate(self.real_thumb, self.real_thumb,
                               has_private_key=self.real_has_key)
        return super().certificate(serial, thumbprint)


def b64(data):
    return base64.b64encode(data).decode()


class ProtocolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.backend = FakeBackend()
        self.plugin = Plugin(self.backend, self.tmp.name + "/tasks.db",
                             self.tmp.name + "/plugin.log")

    def tearDown(self):
        self.backend.gate.set()
        self.plugin.close()
        self.tmp.cleanup()

    def get(self, command, query=""):
        status, ctype, body = self.plugin.handle("GET", command, Params(query), b"")
        return status, body

    def post(self, command, query, doc):
        status, ctype, body = self.plugin.handle("POST", command, Params(query), b64(doc).encode())
        return status, body

    def post_raw(self, command, query, body):
        status, ctype, out = self.plugin.handle("POST", command, Params(query), body)
        return status, out

    # -- simple GET commands --------------------------------------------
    def test_ping_and_getver(self):
        for cmd in ("PING", "GETVER"):
            status, body = self.get(cmd)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {"Status": True, "Data": VERSION, "Errors": []})

    def test_tryuseplugin(self):
        status, body = self.get("TRYUSEPLUGIN")
        self.assertEqual(json.loads(body), {"Status": True, "Data": None, "Errors": []})

    def test_unknown_command_uses_error_prefix(self):
        status, body = self.get("NOPE")
        self.assertEqual(status, 200)
        self.assertEqual(body, '#Error#ReglamentException Unknown command "NOPE"'.encode())

    def test_options(self):
        status, ctype, body = self.plugin.handle("OPTIONS", "GETSIGN", Params(""), b"")
        self.assertEqual((status, ctype, body), (200, "text/html; charset=utf-8",
                                                 b"<HTML><BODY><B>200 OK</B></BODY></HTML>"))

    # -- certificates ----------------------------------------------------
    def test_enumcerts(self):
        status, body = self.get("ENUMCERTS")
        parsed = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(list(parsed["Data"][0]), [
            "Serial", "Thumbprint", "Subject", "SubjectName", "Issuer",
            "IssuerName", "SubjectFIO", "ValidFrom", "ValidFor"])
        self.assertEqual(parsed["Data"][0]["Serial"], "01AB")
        self.assertEqual(parsed["Data"][0]["Thumbprint"], "A" * 40)
        # ENUMCERTS lists qualified private-key certs (excludes qualified=False
        # "04ff"); ENUMALLCERTS additionally requires validity.
        enum = json.loads(self.get("ENUMCERTS")[1])["Data"]
        self.assertEqual({c["Serial"] for c in enum}, {"01AB", "03EF"})
        self.assertEqual(len(json.loads(self.get("ENUMALLCERTS")[1])["Data"]), 1)
        self.assertEqual(len(json.loads(self.get("ENUMCERTS", "onlyValid=true")[1])["Data"]), 1)

    def test_unqualified_cert_excluded_from_enum_but_found_by_lookup(self):
        # "04ff" (qualified=False, has key) is not enumerated...
        enum = json.loads(self.get("ENUMCERTS")[1])["Data"]
        self.assertNotIn("04FF", {c["Serial"] for c in enum})
        # ...but a direct GETCERTBODY / CHECKCERTANDCLUE lookup still finds it.
        status, body = self.get("GETCERTBODY", "CertThumb=" + "d" * 40)
        self.assertEqual((status, json.loads(body)["Data"]), (200, b64(b"cert4")))
        status, body = self.get("CHECKCERTANDCLUE", "CertThumb=" + "d" * 40)
        self.assertEqual(json.loads(body), {"Status": True, "Data": None, "Errors": []})

    def test_enumcerts_empty(self):
        status, body = self.get("ENUMCERTS", "inn=0000")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"Status": False, "Data": None,
                                            "Errors": ["сертификаты не найдены"]})

    def test_getcertbody(self):
        status, body = self.get("GETCERTBODY")
        self.assertEqual(json.loads(body)["Errors"], [MSG_NO_SN])
        status, body = self.get("GETCERTBODY", "CertThumb=" + "A" * 40)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["Data"], b64(b"certificate"))
        status, body = self.get("GETCERTBODY", "CertSN=1AB")
        self.assertEqual(json.loads(body)["Data"], b64(b"certificate"))
        status, body = self.get("GETCERTBODY", "CertThumb=ff")
        self.assertEqual(json.loads(body)["Errors"], ["сертификат с отпечатком: ff не найден"])
        status, body = self.get("GETCERTBODY", "CertSN=ff")
        self.assertEqual(json.loads(body)["Errors"], ["сертификат с SN: ff не найден"])

    def test_checkcertandclue(self):
        status, body = self.get("CHECKCERTANDCLUE", "CertThumb=" + "b" * 40)
        self.assertEqual(json.loads(body)["Errors"], ["Ключевой носитель не найден"])
        status, body = self.get("CHECKCERTANDCLUE", "CertThumb=" + "e" * 40)
        self.assertEqual(json.loads(body)["Errors"], ["Сертификат не найден"])
        status, body = self.get("CHECKCERTANDCLUE", "CertThumb=" + "a" * 40)
        self.assertEqual(json.loads(body), {"Status": True, "Data": None, "Errors": []})

    def test_checkcertandclue_post_cert_body(self):
        import base64
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from tests.test_csp_backend import make_cert
        der = make_cert()
        thumb = x509.load_der_x509_certificate(der).fingerprint(hashes.SHA1()).hex()
        b64 = base64.b64encode(der)
        self.backend.real_thumb = thumb
        # key present -> Status true, Data null (matches the running original)
        self.backend.real_has_key = True
        status, body = self.post_raw("CHECKCERTANDCLUE", "", b64)
        self.assertEqual((status, __import__("json").loads(body)),
                         (200, {"Status": True, "Data": None, "Errors": []}))
        # valid cert, no key in store -> lowercase POST-path message
        self.backend.real_has_key = False
        status, body = self.post_raw("CHECKCERTANDCLUE", "", b64)
        self.assertEqual(__import__("json").loads(body)["Errors"], ["ключевой носитель не найден"])
        # not a certificate
        status, body = self.post_raw("CHECKCERTANDCLUE", "", base64.b64encode(b"nope"))
        self.assertEqual(__import__("json").loads(body)["Errors"],
                         ["Переданные данные не являются сертификатом безопасности"])
        status, body = self.post_raw("CHECKCERTANDCLUE", "", b"")
        self.assertEqual(__import__("json").loads(body)["Errors"],
                         ["Переданные данные не являются сертификатом безопасности"])

    # -- crypto tasks ----------------------------------------------------
    def test_sync_sign(self):
        status, body = self.post("GETSIGN_SYNC", "CertSN=01AB&TaskId=abc", b"payload")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"Status": True, "Data": b64(b"result:payload"),
                                            "Errors": []})

    def test_sync_sign_error(self):
        status, body = self.post("GETSIGN_SYNC", "CertThumb=" + "a" * 40, b"fail")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"Status": False, "Data": None, "Errors": ["boom"]})

    def test_missing_certificate_selector(self):
        status, body = self.post("GETSIGN", "", b"x")
        self.assertEqual(json.loads(body)["Errors"], [MSG_NO_SN_SIGN])
        status, body = self.post("DECRYPT_SEDO_RESPONSE", "", b"x")
        self.assertEqual(json.loads(body)["Errors"], [MSG_NO_SN_DEC])
        status, body = self.post("SIGN_SEDO_REQUEST", "fss_nom=1", b"x")
        self.assertEqual(body.decode(), "#Error#ReglamentException " + MSG_NO_SN_ESK)
        # DECRYPT has no selector check; the CSP picks the recipient key.
        status, body = self.post("DECRYPT_SYNC", "", b"enc")
        self.assertTrue(json.loads(body)["Status"])

    def test_fss_number_validation(self):
        status, body = self.post("SIGN_POVED_REQUEST", "CertSN=01ab", b"x")
        self.assertEqual(json.loads(body)["Errors"], [MSG_NO_FSS_NUM])
        status, body = self.post("SIGN_POVED_REQUEST", "CertSN=01ab&fss_nom=12a", b"x")
        self.assertEqual(json.loads(body)["Errors"], [MSG_BAD_FSS_NUM])
        status, body = self.post("SIGN_POVED_REQUEST_SYNC", "CertSN=01ab&fss_nom=123", b"x")
        self.assertTrue(json.loads(body)["Status"])
        self.assertEqual(self.plugin.db.list_all()[0].str_param, "123")

    def test_async_sign_and_result(self):
        self.backend.gate.clear()
        status, body = self.post("GETSIGN", "CertThumb=" + "A" * 40 + "&TaskId={ABC-1}", b"payload")
        self.assertEqual(json.loads(body), {"Status": True, "Data": "abc1", "Errors": []})
        status, body = self.get("GETRESULT", "Id=abc1")
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["Errors"], [MSG_IN_PROGRESS])
        self.backend.gate.set()
        task = self.plugin.db.wait_status("abc1", 2)
        self.assertEqual(task.status, 2)
        status, body = self.get("GETRESULT", "taskId=abc1")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["Data"], b64(b"result:payload"))
        self.assertEqual(task.cert_thumb, "a" * 40)

    def test_getresult_errors(self):
        status, body = self.get("GETRESULT")
        self.assertEqual((status, json.loads(body)["Errors"]), (401, [MSG_NO_TASKID]))
        status, body = self.get("GETRESULT", "Id=nope")
        self.assertEqual((status, json.loads(body)["Errors"]),
                         (500, ["Криптозадание с Id=nope не найдено"]))
        self.post("GETSIGN_SYNC", "CertSN=01ab&TaskId=bad", b"fail")
        status, body = self.get("GETRESULT", "Id=bad")
        self.assertEqual((status, json.loads(body)["Errors"]), (500, ["boom"]))

    def test_selector_validation(self):
        status, body = self.post("GETSIGN_SYNC", "CertThumb=-dn", b"doc")
        self.assertEqual(json.loads(body)["Errors"], ["сертификат с отпечатком: -dn не найден"])
        status, body = self.post("GETSIGN_SYNC", "CertSN=zz%00", b"doc")
        self.assertEqual(json.loads(body)["Errors"], ["сертификат с SN: zz\x00 не найден"])
        self.assertEqual(self.plugin.db.list_all(), [])
        status, body = self.post("GETSIGN_SYNC", "CertSN=0x01:AB", b"doc")
        self.assertTrue(json.loads(body)["Status"])

    def test_cleanup_drops_old_rows(self):
        from stek_plugin.taskdb import TIME_FMT
        self.post("GETSIGN_SYNC", "CertSN=01ab&TaskId=old", b"doc")
        self.post("GETSIGN_SYNC", "CertSN=01ab&TaskId=mid", b"doc")
        conn = self.plugin.db._conn
        conn.execute("UPDATE CRYPTO_TASKS SET START_TIME=? WHERE ID='old'",
                     ((datetime.now() - timedelta(days=31)).strftime(TIME_FMT),))
        conn.execute("UPDATE CRYPTO_TASKS SET START_TIME=? WHERE ID='mid'",
                     ((datetime.now() - timedelta(days=8)).strftime(TIME_FMT),))
        self.plugin.db.cleanup()
        tasks = {t.id: t for t in self.plugin.db.list_all()}
        self.assertNotIn("old", tasks)
        self.assertEqual((tasks["mid"].in_data, tasks["mid"].out_data), (b"", b""))

    def test_generated_task_id_format(self):
        status, body = self.post("GETSIGN", "CertSN=01ab", b"payload")
        task_id = json.loads(body)["Data"]
        self.assertRegex(task_id, r"^[0-9a-f]{31}$")
        self.assertRegex(new_task_id(), r"^[0-9a-f]{31}$")

    def test_getloginfo(self):
        self.post("GETSIGN_SYNC", "CertSN=01ab&TaskId=t1", b"doc")
        self.post("GETSIGN_SYNC", "CertThumb=" + "a" * 40 + "&TaskId=t2", b"fail")
        status, body = self.get("GETLOGINFO")
        parsed = json.loads(body)
        self.assertEqual(status, 200)
        self.assertTrue(parsed["Status"])
        by_id = {r["Id"]: r for r in parsed["Data"]}
        ok, bad = by_id["t1"], by_id["t2"]
        self.assertEqual(list(ok), ["StartTime", "ModifyTime", "Serial", "Status", "Type",
                                    "Params", "InData", "Result", "Id"])
        self.assertEqual(list(bad), ["StartTime", "ModifyTime", "Thumbprint", "Status", "Type",
                                     "Params", "InData", "Error", "Id"])
        self.assertEqual((ok["Status"], ok["Type"], ok["InData"], ok["Result"]),
                         ("Success", "DetachedSign", b64(b"doc"), b64(b"result:doc")))
        self.assertEqual((bad["Status"], bad["Error"]), ("Error", "boom"))
        self.assertRegex(ok["StartTime"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        status, body = self.get("GETLOGINFO", "TaskId=t2")
        self.assertEqual(len(json.loads(body)["Data"]), 1)
        status, body = self.get("GETLOGINFO", "TaskId=zz")
        self.assertEqual(json.loads(body)["Errors"], ["КЗ с Id=zz не найдено в базе"])

    def test_getlogfile(self):
        with open(self.plugin.log_path, "w") as fh:
            fh.write("log line\n")
        status, body = self.get("GETLOGFILE")
        self.assertEqual(json.loads(body)["Data"], b64(b"log line\n"))


class DocumentDecodeTest(unittest.TestCase):
    def test_lenient_base64(self):
        self.assertEqual(decode_document(b"aGVs\r\nbG8="), b"hello")
        self.assertEqual(decode_document(b"aGVsbG8"), b"hello")
        self.assertEqual(decode_document(b"aGVsbG8=trailing"), b"hello")
        self.assertEqual(decode_document(b""), b"")
        self.assertEqual(decode_document(b"aGVsbG8x"), b"hello1")
        self.assertEqual(decode_document(b"aGVsbG8xY"), b"hello1")   # len % 4 == 1


class ParamsTest(unittest.TestCase):
    def test_document_never_returns_known_param(self):
        self.assertEqual(Params("CertThumb=" + "a" * 40).document(), b"")
        self.assertEqual(Params("CertThumb=aa&Data=aGVsbG8=").document(), b"aGVsbG8=")
        self.assertEqual(Params("aGVsbG8=").document(), b"")   # bare body: key without value


if __name__ == "__main__":
    unittest.main()
