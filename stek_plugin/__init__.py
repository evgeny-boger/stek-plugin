"""Стэк.Плагин (StekTrustPlugin) — Python reproduction.

Reverse-engineered from stek.plugin.tar / stek-plugin_2.7.0.9_amd64.deb
(original is a FreePascal/Lazarus GTK2 application using Indy TIdHTTPServer,
SQLite3 and CryptoPro CSP through the Linux CryptoAPI shim libcpcsp).
"""

VERSION = "2.7.0.9"
SERVER_SOFTWARE = "TRUST"
PLUGIN_NAME = "Стэк.Плагин"

# Original binds 127.0.0.1:18080 (DefaultPort = 0x46A0 from the embedded
# Lazarus form resource of THttpAccess.HTTPServer: TIdHTTPServer).
BIND_HOST = "127.0.0.1"
BIND_PORT = 18080

# URL prefix accepted by HTTPServerCommandGet ("/TRUST/GETSIGN?...").
URL_PREFIX = "/TRUST/"

# Database / log file names used by the original next to the executable.
DB_NAME = "StekTrustPlugin.gdb"
LOG_NAME = "StekTrustPlugin.log"

# The command handler sets this content type in its prologue for every
# request (0x4683d8); no handler overrides it in practice.
CONTENT_TYPE_JSON = "application/json; charset=utf-8"
CONTENT_TYPE_HTML = "text/html; charset=utf-8"
# Indy's default body for a bare 200 (OPTIONS preflight).
OPTIONS_BODY = b"<HTML><BODY><B>200 OK</B></BODY></HTML>"

# Every exception escaping a command handler is reported as ContentText
# '#Error#' + E.ClassName + ' ' + E.Message with the default HTTP status
# (0x468c03, 0x469a03), e.g. '#Error#ReglamentException Unknown command "X"'.
# '#OK#' (0x468aeb) is unreachable dead code in 2.7.0.9.
ERROR_PREFIX = "#Error#"

# CRYPTO_TASKS.TTYPE values (recovered from the GETLOGINFO serializer).
TASK_DETACHED_SIGN = 0      # "DetachedSign"      - GETSIGN
TASK_ATTACHED_SIGN = 1      # "AttachedSign"      - GETSIGN_ATT
TASK_XMLDSIGN = 2           # "XMLDsig"           - GET_XML_SIGN
TASK_BUILD_POVED = 3        # "BuildPOVEDRequest" - SIGN_POVED_REQUEST
TASK_BUILD_SEDO = 4         # "BuildSEDORequest"  - SIGN_SEDO_REQUEST
TASK_DECRYPT = 5            # "Decrypt"           - DECRYPT
TASK_DECRYPT_FSS = 6        # "DecryptFssResponse"- DECRYPT_POVED_RESPONSE (sic)
TASK_DECRYPT_SEDO = 7       # (no name in serializer) DECRYPT_SEDO/FSS_RESPONSE
TASK_SIGN_HASH = 8          # "SignHash"          - SIGN_HASH

# Names emitted by the serializer at 0x4675e1..0x467668.  TTYPE 7 has no
# case label there, so the original emits an empty "Type" for it.
TASK_TYPE_NAMES = {
    TASK_DETACHED_SIGN: "DetachedSign",
    TASK_ATTACHED_SIGN: "AttachedSign",
    TASK_XMLDSIGN: "XMLDsig",
    TASK_BUILD_POVED: "BuildPOVEDRequest",
    TASK_BUILD_SEDO: "BuildSEDORequest",
    TASK_DECRYPT: "Decrypt",
    TASK_DECRYPT_FSS: "DecryptFssResponse",
    TASK_DECRYPT_SEDO: "",
    TASK_SIGN_HASH: "SignHash",
}

# CRYPTO_TASKS.STATUS values.
STATUS_NEW = 0        # "New"
STATUS_WAIT = 1       # "Wait"  (in progress)
STATUS_SUCCESS = 2    # "Success"
STATUS_ERROR = 3      # "Error"

STATUS_NAMES = {0: "New", 1: "Wait", 2: "Success", 3: "Error"}

# --- Russian messages, byte-identical to the original .rodata -------------
MSG_NO_SN = "Не указан SN (или Thumbprint) сертификата"
MSG_NO_SN_SIGN = "Не указан SN (или Thumbprint) сертификата для ЭП"
MSG_NO_SN_DEC = "Не указан SN (или Thumbprint) сертификата для расшифрования"
MSG_NO_SN_ESK = "Ошибка! Не указан SN сертификата для ЭП"
MSG_NO_TASKID = "Не указан Id криптозадания"
MSG_IN_PROGRESS = "В стадии выполнения"
MSG_TASK_NOT_FOUND = "Криптозадание с Id={id} не найдено"
MSG_TASK_NOT_FOUND_DB = "КЗ с Id={id} не найдено в базе"
MSG_TASK_TIMEOUT = "Время ожидания выполнения криптозадания истекло"
MSG_CRYPTO_ERROR = "Ошибка выполнения криптозадачи"
MSG_NO_FSS_NUM = "Не указан рег. номер ФСС"
MSG_BAD_FSS_NUM = "Указан некорректный рег. номер ФСС"
MSG_CERTS_NOT_FOUND = "сертификаты не найдены"       # language flag = 1
MSG_CERTS_NOT_FOUND_EN = "certificates not founded"  # language flag = 0 / log
MSG_CERT_NOT_FOUND = "Сертификат не найден"
MSG_CERT_THUMB_NOT_FOUND = "сертификат с отпечатком: {value} не найден"
MSG_CERT_SN_NOT_FOUND = "сертификат с SN: {value} не найден"
MSG_KEY_NOT_FOUND = "Ключевой носитель не найден"          # GET lookup path (0xb06e80)
MSG_KEY_NOT_FOUND_POST = "ключевой носитель не найден"      # POST cert-body path (0xb061b8)
MSG_NO_CMS = "Переданные данные не являются сертификатом безопасности"
MSG_UNKNOWN_CMD = 'Unknown command "{command}"'
MSG_DB_CREATED = "Создана база данных: "
MSG_DB_ERROR = "Ошибка при создании базы данных: "
MSG_HTTP_ERROR = "Ошибка запуска HTTP: "
MSG_SHUTDOWN = "Завершение работы плагина"

WELCOME_HTML = "<html><body><b>Вас приветствует Плагин !</b></body></html>"

# X.509 OID -> RDN key table recovered from .rodata (0xb08440..0xb09220) and
# confirmed against the original's ENUMCERTS output (GN=, streetAddress=).
OID_INN = "1.2.643.3.131.1.1"      # ИНН физлица
OID_INNLE = "1.2.643.100.4"        # ИНН юрлица
OID_OGRN = "1.2.643.100.1"
OID_OGRNIP = "1.2.643.100.5"
OID_SNILS = "1.2.643.100.3"
OID_EMAIL = "1.2.840.113549.1.9.1"
OID_UNSTRUCTURED = "1.2.840.113549.1.9.2"
OID_STREET = "2.5.4.9"
OID_TITLE = "2.5.4.12"
OID_RNS_FSS = "1.2.643.3.141.1.1"
OID_KP_FSS = "1.2.643.3.141.1.2"

# ENUMCERTS lists only "qualified" certificates — those whose subject carries
# a Russian personal/organisation identifier.  Confirmed against the running
# original: a self-signed CN=mykey test cert (email+CN only, but with a usable
# GOST key) is excluded from ENUMCERTS/ENUMALLCERTS, while it is still returned
# by GETCERTBODY / CHECKCERTANDCLUE lookups.  (The exact predicate lives in the
# CryptoPro store wrapper and could not be traced further; "has one of these
# OIDs" reproduces the observed set and matches the plugin's INN-centric domain.)
QUALIFIED_SUBJECT_OIDS = frozenset({OID_INN, OID_INNLE, OID_OGRN, OID_OGRNIP, OID_SNILS})

OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.42": "GN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "S",
    "2.5.4.9": "streetAddress",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "T",
    OID_EMAIL: "E",
    OID_UNSTRUCTURED: "unstructuredName",
    OID_INN: "INN",
    OID_INNLE: "INNLE",
    OID_OGRN: "OGRN",
    OID_OGRNIP: "OGRNIP",
    OID_SNILS: "SNILS",
    OID_RNS_FSS: "RNS-FSS",
    OID_KP_FSS: "KP-FSS",
}

# GOST algorithm OIDs.
OID_GOST3410_2012_256 = "1.2.643.7.1.1.1.1"
OID_GOST3410_2012_512 = "1.2.643.7.1.1.1.2"
OID_GOST3411_2012_256 = "1.2.643.7.1.1.2.2"
OID_GOST3411_2012_512 = "1.2.643.7.1.1.2.3"
OID_GOST3410_2001 = "1.2.643.2.2.19"
OID_GOST3411_94 = "1.2.643.2.2.9"

# Cleanup policy (recovered SQL):
#   delete from CRYPTO_TASKS where START_TIME < :dt
#   update CRYPTO_TASKS set IN_DATA=NULL,OUT_DATA=NULL where START_TIME < :dt
TASK_TTL_DAYS = 30          # when to delete finished tasks
TASK_BLOB_TTL_DAYS = 7      # when to drop IN/OUT blobs

# Polling interval used by the original dispatcher (Sleep(100) loop).
TASK_POLL_INTERVAL = 0.1
# Long-poll timeout for sync task execution.
TASK_SYNC_TIMEOUT = 120.0
