"""Local HTTP protocol reproduced from StekTrustPlugin 2.7.0.9.

Every status code, message and envelope below is annotated with the
address in the original binary it was recovered from.
"""
import base64
import errno
import logging
import re
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import (CONTENT_TYPE_HTML, CONTENT_TYPE_JSON, DB_NAME, OPTIONS_BODY, ERROR_PREFIX, LOG_NAME, MSG_BAD_FSS_NUM,
               MSG_CERT_NOT_FOUND, MSG_CERT_SN_NOT_FOUND, MSG_CERT_THUMB_NOT_FOUND,
               MSG_CERTS_NOT_FOUND, MSG_CRYPTO_ERROR, MSG_IN_PROGRESS,
               MSG_KEY_NOT_FOUND, MSG_KEY_NOT_FOUND_POST, MSG_NO_CMS, MSG_NO_FSS_NUM, MSG_NO_SN, MSG_NO_SN_DEC,
               MSG_NO_SN_ESK, MSG_NO_SN_SIGN, MSG_NO_TASKID, MSG_TASK_NOT_FOUND,
               MSG_TASK_NOT_FOUND_DB, MSG_UNKNOWN_CMD, SERVER_SOFTWARE, STATUS_NEW,
               STATUS_SUCCESS, STATUS_WAIT, TASK_ATTACHED_SIGN, TASK_BUILD_POVED,
               TASK_BUILD_SEDO, TASK_DECRYPT, TASK_DECRYPT_FSS, TASK_DECRYPT_SEDO,
               TASK_DETACHED_SIGN, TASK_SIGN_HASH, TASK_XMLDSIGN, VERSION, BIND_HOST,
               BIND_PORT)
from .backends.base import normalize_serial
from .params import Params
from .responses import (build_json, build_json_array, cert_entry_json,
                        task_entry_json)
from .taskdb import Task, TaskDB, TaskWorker, new_task_id, normalize_task_id

log = logging.getLogger("stek_plugin")

# POST dispatcher 0x4685d3..0x468899: command -> TTYPE.
COMMAND_TYPES = {
    "GETSIGN": TASK_DETACHED_SIGN,
    "GETSIGN_ATT": TASK_ATTACHED_SIGN,
    "GET_XML_SIGN": TASK_XMLDSIGN,
    "SIGN_HASH": TASK_SIGN_HASH,
    "SIGN_POVED_REQUEST": TASK_BUILD_POVED,
    "SIGN_SEDO_REQUEST": TASK_BUILD_SEDO,
    "DECRYPT": TASK_DECRYPT,
    # Both SEDO and FSS responses share the branch at 0x468808 (TTYPE 7).
    "DECRYPT_FSS_RESPONSE": TASK_DECRYPT_SEDO,
    "DECRYPT_SEDO_RESPONSE": TASK_DECRYPT_SEDO,
    # DECRYPT_POVED_RESPONSE routes to TTYPE 6 (0x468857).
    "DECRYPT_POVED_RESPONSE": TASK_DECRYPT_FSS,
}
SIGN_COMMANDS = ("GETSIGN", "GETSIGN_ATT", "GET_XML_SIGN", "SIGN_HASH")
SEDO_COMMANDS = ("SIGN_POVED_REQUEST", "SIGN_SEDO_REQUEST")
RESPONSE_COMMANDS = ("DECRYPT_FSS_RESPONSE", "DECRYPT_SEDO_RESPONSE",
                     "DECRYPT_POVED_RESPONSE")
GET_COMMANDS = ("PING", "GETVER", "TRYUSEPLUGIN", "GETRESULT", "GETLOGFILE",
                "GETLOGINFO", "ENUMCERTS", "ENUMALLCERTS", "GETCERTBODY",
                "CHECKCERTANDCLUE", "OPTIONS")

# Indy's TIdHTTPServer has no body limit; cap at 64 MiB.
MAX_BODY = 64 * 1024 * 1024
# A bare Base64 body (browser default content type is form-urlencoded).
_BARE_B64 = re.compile(rb"[A-Za-z0-9+/\s]*=*\s*")

_B64_JUNK = re.compile(rb"[^A-Za-z0-9+/=]")


class PluginError(Exception):
    """Mirrors the original's ReglamentException ('#Error#ReglamentException msg')."""
    fpc_class = "ReglamentException"


def decode_document(body: bytes) -> bytes:
    """Lenient Base64 decoder equivalent to 0xa9ac00: characters outside
    the alphabet are skipped, '=' terminates a quantum."""
    cleaned = _B64_JUNK.sub(b"", body)
    if b"=" in cleaned:
        cleaned = cleaned[:cleaned.index(b"=")]
    if len(cleaned) % 4 == 1:          # a dangling sextet carries no byte
        cleaned = cleaned[:-1]
    cleaned += b"=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned)


class Plugin:
    def __init__(self, backend, db_path=DB_NAME, log_path=LOG_NAME):
        self.backend = backend
        self.db = TaskDB(db_path)
        self.db.fail_stale()     # не переисполнять задачи, зависшие с прошлого запуска
        self.db.cleanup()
        self.worker = TaskWorker(self.db, backend)
        self.worker.start()
        # TRYUSEPLUGIN/PING read a global string set at start-up; it is
        # opaque to the client, which only checks Status.
        self.plugin_id = uuid.uuid5(uuid.NAMESPACE_URL, "stek.plugin.python").hex
        self.log_path = log_path

    def close(self):
        self.worker.stop()
        self.db.close()

    # -- request entry point ----------------------------------------------
    def handle(self, method, command, params, body):
        """Returns (status, content_type, body_bytes).

        Any exception becomes ContentText '#Error# <message>' with the
        default status 200 (handlers at 0x468b0c / 0x4699a9).
        """
        command = command.upper()      # the client uses mixed case (e.g. "GetVer")
        sync = command.endswith("_SYNC")
        if sync:
            command = command[:-5]
        try:
            if method == "OPTIONS" or command == "OPTIONS":
                return 200, CONTENT_TYPE_HTML, OPTIONS_BODY
            if method == "POST" and command == "CHECKCERTANDCLUE":
                return self._check_clue(body)      # 0x464110: cert supplied in the body
            if method == "POST" and command in COMMAND_TYPES:
                return self._crypto(command, params, body, sync)
            if command in GET_COMMANDS:
                return self._get(command, params)
            raise PluginError(MSG_UNKNOWN_CMD.format(command=command))
        except PluginError as exc:
            log.info("Request %s: %s", command, exc)
            return 200, CONTENT_TYPE_JSON, f"{ERROR_PREFIX}{exc.fpc_class} {exc}".encode()
        except Exception as exc:  # noqa: BLE001 - mirror FPC try/except
            log.exception("Request %s failed", command)
            text = f"{ERROR_PREFIX}{exc.__class__.__name__} {exc or exc.__class__.__name__}"
            return 200, CONTENT_TYPE_JSON, text.encode()

    # -- GET commands (0x468f40..0x4698ff) -----------------------------------
    def _get(self, command, params):
        json_ = CONTENT_TYPE_JSON
        if command == "PING":            # 0x4669c0
            ok = bool(self.plugin_id)
            return 200, json_, build_json(ok, VERSION if ok else None, raw=True).encode()
        if command == "GETVER":          # 0x466920
            return 200, json_, build_json(True, VERSION, raw=True).encode()
        if command == "TRYUSEPLUGIN":    # 0x4697e8; observed: Status true, Data null
            return 200, json_, build_json(True, None).encode()
        if command == "GETRESULT":       # 0x466cb0
            return self._get_result(params)
        if command == "GETLOGFILE":      # 0x466aa0
            if self.log_path in ("-", ""):   # лог направлен в journald
                return 200, json_, build_json(
                    False, errors=["Логи направляются в journald: "
                                   "journalctl --user -u stek-plugin"]).encode()
            try:
                with open(self.log_path, "rb") as fh:
                    return 200, json_, build_json(True, fh.read()).encode()
            except OSError as exc:
                return 200, json_, build_json(False, errors=[str(exc)]).encode()
        if command == "GETLOGINFO":      # 0x467010
            return self._log_info(params)
        if command in ("ENUMCERTS", "ENUMALLCERTS"):   # 0x4658f0
            return self._enum_certs(command == "ENUMALLCERTS", params)
        if command in ("GETCERTBODY", "CHECKCERTANDCLUE"):  # 0x463c30 / 0x467ca0
            return self._cert_body(command, params)
        raise PluginError(MSG_UNKNOWN_CMD.format(command=command))

    def _enum_certs(self, all_certs, params):
        # Observed on the original: ENUMCERTS lists every private-key
        # certificate (expired included); ENUMALLCERTS lists only the
        # currently valid ones, the same as ENUMCERTS?onlyValid=true.
        try:
            only_valid = all_certs or params.value("onlyValid").lower() == "true"
            certs = self.backend.certificates(True, params.value("inn"), only_valid)
        except Exception as exc:  # 0x469376: ResponseNo := 500
            log.exception("HandleEnumCerts failed")
            return 500, CONTENT_TYPE_JSON, str(exc).encode("utf-8", "replace")
        log.info("HandleEnumCerts,%s,count=%d", params.value("inn"), len(certs))
        if not certs:
            body = build_json_array(False, [], [MSG_CERTS_NOT_FOUND])
        else:
            body = build_json_array(True, [cert_entry_json(c) for c in certs])
        return 200, CONTENT_TYPE_JSON, body.encode()

    def _cert_body(self, command, params):
        sn, thumb = params.value("CertSN"), params.value("CertThumb")
        if not params.has("CertSN") and not params.has("CertThumb"):
            return 200, CONTENT_TYPE_JSON, build_json(False, errors=[MSG_NO_SN]).encode()
        try:
            cert = self.backend.certificate(normalize_serial(sn), normalize_serial(thumb))
        except Exception as exc:  # 0x469628 / 0x469780: ResponseNo := 500
            log.exception("%s failed", command)
            return 500, CONTENT_TYPE_JSON, str(exc).encode("utf-8", "replace")
        if cert is None:
            if command == "CHECKCERTANDCLUE":
                message = MSG_CERT_NOT_FOUND
            elif thumb:
                message = MSG_CERT_THUMB_NOT_FOUND.format(value=thumb)
            else:
                message = MSG_CERT_SN_NOT_FOUND.format(value=sn)
            return 200, CONTENT_TYPE_JSON, build_json(False, errors=[message]).encode()
        if command == "CHECKCERTANDCLUE":
            if not cert.has_private_key:
                return 200, CONTENT_TYPE_JSON, build_json(False, errors=[MSG_KEY_NOT_FOUND]).encode()
            return 200, CONTENT_TYPE_JSON, build_json(True, None).encode()   # observed: Data null
        return 200, CONTENT_TYPE_JSON, build_json(True, cert.der).encode()

    def _check_clue(self, body):
        """POST CHECKCERTANDCLUE (0x464110): the request body is a Base64
        certificate.  Verify it parses, then report whether its private key
        ("clue") is in the local store.  Confirmed against the running
        original: valid cert + key -> Status:true/Data:null; valid cert, no
        key -> "ключевой носитель не найден"; not a certificate ->
        "Переданные данные не являются сертификатом безопасности"."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        der = decode_document(body)
        try:
            cert = (x509.load_pem_x509_certificate(der) if der.startswith(b"-----BEGIN")
                    else x509.load_der_x509_certificate(der))
        except Exception:  # noqa: BLE001 - any parse failure is "not a certificate"
            return 200, CONTENT_TYPE_JSON, build_json(False, errors=[MSG_NO_CMS]).encode()
        thumb = cert.fingerprint(hashes.SHA1()).hex()
        found = self.backend.certificate(thumbprint=thumb)
        if found is None or not found.has_private_key:
            return 200, CONTENT_TYPE_JSON, build_json(False, errors=[MSG_KEY_NOT_FOUND_POST]).encode()
        return 200, CONTENT_TYPE_JSON, build_json(True, None).encode()

    def _get_result(self, params):
        json_ = CONTENT_TYPE_JSON
        # Default ResponseNo for this handler is 401 (0x466d1b).
        if not params.has("Id") and not params.has("taskId"):
            return 401, json_, build_json(False, errors=[MSG_NO_TASKID]).encode()
        task_id = params.value("Id") or params.value("taskId")
        task = self.db.get(task_id)
        if task is None:               # 0x4707a2: status 3 + message
            message = MSG_TASK_NOT_FOUND.format(id=task_id)
            return 500, json_, build_json(False, errors=[message]).encode()
        if task.status in (STATUS_NEW, STATUS_WAIT):   # 0x466ea5
            return 201, json_, build_json(False, errors=[MSG_IN_PROGRESS]).encode()
        if task.status == STATUS_SUCCESS:               # 0x466ef4
            return 200, json_, build_json(True, task.out_data).encode()
        error = task.out_data.decode("utf-8", "replace")  # 0x466f4f
        return 500, json_, build_json(False, errors=[error]).encode()

    def _log_info(self, params):
        task_id = params.value("TaskId") if params.has("TaskId") else ""
        if task_id:
            task = self.db.get(task_id)
            tasks = [task] if task else []
        else:
            tasks = self.db.list_all()
        if not tasks:
            if task_id:
                message = MSG_TASK_NOT_FOUND_DB.format(id=task_id)
                body = build_json(False, errors=[message])
            else:
                body = build_json(True, None)
        else:
            body = build_json_array(True, [task_entry_json(t) for t in tasks])
        return 200, CONTENT_TYPE_JSON, body.encode()

    # -- crypto commands (0x4650d0, 0x464bf0, 0x465520, 0x464770) -----------
    def _crypto(self, command, params, body, sync):
        json_ = CONTENT_TYPE_JSON
        sn, thumb = params.value("CertSN"), params.value("CertThumb")
        # The original keys on parameter *presence*, not value: an empty
        # CertThumb= is "present" and proceeds to a (failing) lookup.
        has_sn = params.has("CertSN") or params.has("CertThumb")
        if command in SIGN_COMMANDS and not has_sn:
            return 200, json_, build_json(False, errors=[MSG_NO_SN_SIGN]).encode()
        if command in RESPONSE_COMMANDS and not has_sn:
            return 200, json_, build_json(False, errors=[MSG_NO_SN_DEC]).encode()
        if command in SEDO_COMMANDS:
            if not params.has("CertSN"):
                raise PluginError(MSG_NO_SN_ESK)
            if not params.has("fss_nom"):
                return 200, json_, build_json(False, errors=[MSG_NO_FSS_NUM]).encode()
            if not params.value("fss_nom").isdigit():
                return 200, json_, build_json(False, errors=[MSG_BAD_FSS_NUM]).encode()
        task_id = (normalize_task_id(params.value("TaskId"))
                   if params.has("TaskId") else "") or new_task_id()
        if not self.backend.validate_selector(sn, thumb):
            message = (MSG_CERT_THUMB_NOT_FOUND.format(value=thumb) if thumb
                       else MSG_CERT_SN_NOT_FOUND.format(value=sn))
            return 200, json_, build_json(False, errors=[message]).encode()
        task = Task(id=task_id, ttype=COMMAND_TYPES[command],
                    cert_sn=normalize_serial(sn), cert_thumb=normalize_serial(thumb),
                    str_param=params.value("fss_nom"),
                    in_data=decode_document(body))
        if not sync:                     # 0x4653e1: enqueue, answer with the id
            self.db.insert(task)
            return 200, json_, build_json(True, task.id, raw=True).encode()
        task = self.worker.execute_sync(task)   # 0x463800
        if task.status == STATUS_SUCCESS:
            return 200, json_, build_json(True, task.out_data).encode()
        return 200, json_, build_json(False, errors=[task.error or MSG_CRYPTO_ERROR]).encode()


def handler_factory(plugin):
    class Handler(BaseHTTPRequestHandler):
        server_version = SERVER_SOFTWARE
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = 30                 # не давать соединению висеть вечно

        def version_string(self): return SERVER_SOFTWARE

        def do_OPTIONS(self): self._handle("OPTIONS")
        def do_GET(self): self._handle("GET")
        def do_POST(self): self._handle("POST")

        def _handle(self, method):
            parsed = urlsplit(self.path)
            command = parsed.path.rstrip("/").rsplit("/", 1)[-1].upper()
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                length = -1
            if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                self.close_connection = True
                return self._send(411, CONTENT_TYPE_JSON, b"")
            if length < 0 or length > MAX_BODY:
                self.close_connection = True
                return self._send(400 if length < 0 else 413, CONTENT_TYPE_JSON, b"")
            body = self.rfile.read(length) if length else b""
            # Indy: UnparsedParams = query string (GET / raw POST) or the form
            # body (application/x-www-form-urlencoded POST); the document is
            # the raw body, or the non-parameter form value ("Data=...").
            ctype = self.headers.get("Content-Type", "")
            raw = parsed.query
            document = body
            if body and "x-www-form-urlencoded" in ctype.lower():
                form_text = body.decode("utf-8", "replace")
                form = Params(form_text)
                if form.has_known():
                    raw = "&".join(x for x in (raw, form_text) if x)
                # A bare "<b64>" body (jQuery default content type) is used
                # as-is; "Data=<b64>" / "CertThumb=..." bodies are forms.
                if not _BARE_B64.fullmatch(body):
                    document = form.document()
                    if b" " in document:
                        log.warning("form-encoded document contains spaces: "
                                    "'+' must be sent as %%2B")
            log.info('<<Request :"%s" from IP=%s', self.path, self.client_address[0])
            status, content_type, response = plugin.handle(method, command, Params(raw), document)
            self._send(status, content_type, response)
            log.info('>>Request :"%s" , HTTP RESULT=%d', self.path, status)

        def _send(self, status, content_type, body):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if content_type == CONTENT_TYPE_JSON:
                self.send_header("Content-Encoding", "utf-8")   # Indy emits this too
            self.send_header("Content-Length", str(len(body)))
            # CORS headers set in the handler prologue (0x468349..0x4683cf).
            origin = self.headers.get("Origin")
            self.send_header("Access-Control-Allow-Origin", origin if origin else "*")
            self.send_header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
            self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
            self.send_header("Access-Control-Max-Age", "86400")
            self.send_header("Vary", "Accept-Encoding, Origin")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def log_message(self, fmt, *args): log.debug(fmt, *args)
    return Handler


def serve(plugin, host=BIND_HOST, port=BIND_PORT):
    import signal
    import threading as _threading
    # 127.0.0.1:PORT is shared across the whole machine, so only one instance
    # can own it. If it is already served (another user session, or the
    # original StekTrustPlugin), exit cleanly (status 0) so systemd does not
    # restart-loop; the instance that holds the port serves every local client.
    try:
        server = ThreadingHTTPServer((host, port), handler_factory(plugin))
    except OSError as exc:
        plugin.close()
        if exc.errno == errno.EADDRINUSE:
            log.warning("%s:%d already in use; another StekTrustPlugin instance "
                        "is serving it — exiting.", host, port)
            return
        raise
    # systemd шлёт SIGTERM — завершаемся штатно (shutdown() из другого потока).
    def _stop(_signum, _frame):
        _threading.Thread(target=server.shutdown, daemon=True).start()
    try:
        signal.signal(signal.SIGTERM, _stop)
    except ValueError:
        pass                          # не главный поток (например, в тестах)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        plugin.close()
