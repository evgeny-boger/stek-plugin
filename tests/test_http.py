"""Socket-level tests: CORS headers, routing, sync/async flow over HTTP."""
import base64
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from stek_plugin.server import Plugin, handler_factory
from tests.test_protocol import FakeBackend


class HttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.plugin = Plugin(FakeBackend(), cls.tmp.name + "/tasks.db",
                            cls.tmp.name + "/plugin.log")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(cls.plugin))
        cls.base = "http://127.0.0.1:%d/TRUST/" % cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.plugin.close()
        cls.tmp.cleanup()

    def request(self, path, data=None, method=None, headers=None):
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            with err:
                return err.code, dict(err.headers), err.read()

    def test_cors_preflight(self):
        status, headers, body = self.request("GETSIGN", method="OPTIONS",
                                             headers={"Origin": "http://example"})
        self.assertEqual((status, body), (200, b"<HTML><BODY><B>200 OK</B></BODY></HTML>"))
        self.assertEqual(headers["Access-Control-Allow-Origin"], "http://example")
        self.assertEqual(headers["Access-Control-Allow-Methods"], "POST, GET, OPTIONS")
        self.assertEqual(headers["Access-Control-Allow-Headers"],
                         "Origin, X-Requested-With, Content-Type, Accept")
        self.assertEqual(headers["Access-Control-Max-Age"], "86400")
        self.assertEqual(headers["Vary"], "Accept-Encoding, Origin")
        self.assertEqual(headers["Server"], "TRUST")

    def test_ping(self):
        status, headers, body = self.request("PING")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(headers["Content-Encoding"], "utf-8")
        self.assertEqual(headers["Access-Control-Allow-Origin"], "*")
        self.assertTrue(json.loads(body)["Status"])

    def test_lowercase_path_and_prefix(self):
        status, _, body = self.request("ping")
        self.assertTrue(json.loads(body)["Status"])

    def test_sync_sign_raw_body(self):
        doc = base64.b64encode(b"hello")
        status, _, body = self.request("GETSIGN_SYNC?CertThumb=" + "a" * 40, data=doc,
                                       headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 200)
        self.assertEqual(base64.b64decode(json.loads(body)["Data"]), b"result:hello")

    def test_sync_sign_form_body(self):
        doc = base64.b64encode(b"hello").decode()
        form = ("CertThumb=" + "a" * 40 + "&Data=" + doc).encode()
        status, _, body = self.request("GETSIGN_ATT_SYNC", data=form,
                                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(base64.b64decode(json.loads(body)["Data"]), b"result:hello")

    def test_form_body_without_thumb_in_form(self):
        doc = base64.b64encode(b"hello").decode()
        status, _, body = self.request("GETSIGN_SYNC?CertThumb=" + "a" * 40,
                                       data=("Data=" + doc).encode(),
                                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(base64.b64decode(json.loads(body)["Data"]), b"result:hello")

    def test_bare_base64_body_with_form_content_type(self):
        # urllib/jQuery default: application/x-www-form-urlencoded, bare payload
        for doc, suffix in ((b"hi+there", b""), (b"a", b""), (b"ab", b"\n"),
                            (b"abc", b"\r\n"), (b"\xff\xfe\xfd\xfc", b"")):
            status, _, body = self.request("GETSIGN_SYNC?CertThumb=" + "a" * 40,
                                           data=base64.b64encode(doc) + suffix)
            self.assertEqual(base64.b64decode(json.loads(body)["Data"]), b"result:" + doc, doc)

    def test_form_body_without_document_signs_nothing(self):
        status, _, body = self.request("GETSIGN_SYNC", data=("CertThumb=" + "a" * 40).encode(),
                                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(base64.b64decode(json.loads(body)["Data"]), b"result:")

    def test_bad_content_length(self):
        import socket
        for header, expected in (("Content-Length: -1", 400), ("Content-Length: x", 400),
                                 ("Content-Length: 99999999999", 413),
                                 ("Transfer-Encoding: chunked", 411)):
            with socket.create_connection(self.server.server_address, timeout=5) as sock:
                sock.sendall(("POST /TRUST/PING HTTP/1.1\r\nHost: x\r\n" + header +
                              "\r\n\r\n").encode())
                head = sock.recv(64).decode()
            self.assertIn("HTTP/1.1 %d" % expected, head, header)

    def test_async_roundtrip(self):
        status, _, body = self.request("GETSIGN?CertSN=01ab&TaskId=http1",
                                       data=base64.b64encode(b"doc"))
        self.assertEqual(json.loads(body)["Data"], "http1")
        self.plugin.db.wait_status("http1", 2)
        status, _, body = self.request("GETRESULT?Id=http1")
        self.assertEqual(status, 200)
        self.assertEqual(base64.b64decode(json.loads(body)["Data"]), b"result:doc")

    def test_getresult_status_codes(self):
        status, _, body = self.request("GETRESULT")
        self.assertEqual(status, 401)
        status, _, body = self.request("GETRESULT?Id=missing")
        self.assertEqual(status, 500)

    def test_unknown_command(self):
        status, _, body = self.request("WHATEVER")
        self.assertEqual((status, body), (200, b'#Error#ReglamentException Unknown command "WHATEVER"'))


if __name__ == "__main__":
    unittest.main()


class BindConflictTest(unittest.TestCase):
    def test_second_instance_exits_cleanly_on_busy_port(self):
        import socket, tempfile
        from stek_plugin.server import Plugin, serve
        from tests.test_protocol import FakeBackend
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen()
        port = s.getsockname()[1]
        try:
            plugin = Plugin(FakeBackend(), ":memory:", tempfile.mkdtemp() + "/log")
            # must return (not raise) when the port is already taken
            serve(plugin, "127.0.0.1", port)
        finally:
            s.close()
