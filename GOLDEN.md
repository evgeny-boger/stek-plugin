# Golden comparison — StekTrustPlugin 2.7.0.9 vs. this reproduction

The original Linux binary was run live on this host (its GTK tray needs a
display; `libsqlite3.so` is loaded by the name `libsqlite3.so`, so start it
with `LD_LIBRARY_PATH` pointing at a dir that has that exact soname). Every
command below was issued to the original and to this reproduction with the
same request; the table records the *semantic* response. JSON whitespace is
deliberately not reproduced (the original pretty-prints with CRLF; we use
`json.dumps`), so bytes differ but the structure matches.

Signing used the CryptoPro **test certificate** `CN=mykey`,
`E=test@cryptopro.ru` (software container, thumbprint
`10bd0d35317f260ada2380e93541489c6a98f77f`), so no personal key was touched.

## Confirmed identical (semantically)

| Command | Original | Reproduction |
|---|---|---|
| `PING`, `GETVER` | `{"Status":true,"Data":"2.7.0.9","Errors":[]}` | same |
| `TRYUSEPLUGIN` | `Status:true, Data:null` | same |
| `OPTIONS` (any) | `200`, `text/html; charset=utf-8`, `<HTML><BODY><B>200 OK</B></BODY></HTML>` | same |
| `ENUMCERTS` | **qualified** private-key certs (subject has INN/OGRN/SNILS/…), expired included, upper-case Serial/Thumbprint | same |
| `ENUMALLCERTS` | qualified + currently-valid (= `ENUMCERTS?onlyValid=true`) | same |
| `ENUMCERTS?inn=` | filter; empty → `Status:false, ["сертификаты не найдены"]` | same |
| name format | `GN=`, `streetAddress=`, reversed RDN order, no quoting | same |
| `GETCERTBODY` | `Data` = base64 DER; errors `Не указан…` / `сертификат с отпечатком: X не найден` / `… с SN: X …` | same |
| `CHECKCERTANDCLUE` (see below) | method-dependent | same (verified all 8 forms) |
| `GETLOGFILE` | `Data` = base64 log text | same |
| `GETSIGN_SYNC` / `_ATT_SYNC` | `Data` = base64 CMS SignedData (verifies with `cryptcp -verify`) | same (verified) |
| `SIGN_HASH_SYNC` | `Data` = base64 raw signature (64 B) | same (pycades backend) |
| `DECRYPT_SYNC` | `Data` = base64 plaintext | same |
| unknown command | `200`, `#Error#ReglamentException Unknown command "X"` | same |
| exception framing | `#Error#<ClassName> <message>` | same |
| headers | `Content-Type: application/json; charset=utf-8`, `Content-Encoding: utf-8`, all CORS headers, `Server: TRUST` | same |
| `GETRESULT` no id | `401` | same |

## ENUMCERTS "qualified" filter

`ENUMCERTS`/`ENUMALLCERTS` list only certificates whose subject carries a
Russian identifier OID (INN 1.2.643.3.131.1.1, INNLE 1.2.643.100.4, OGRN,
OGRNIP, SNILS). Verified live: a self-signed `CN=mykey` test certificate with
a **usable** GOST key (it signs fine) but only email+CN in its subject is
excluded from both listings, while it is still returned by `GETCERTBODY` and
accepted by `CHECKCERTANDCLUE` lookups. The exact predicate lives in the
CryptoPro store wrapper; "subject has one of those OIDs" reproduces the
observed set exactly and matches the plugin's tax/gov domain. The filter
applies only to enumeration, never to direct thumbprint/serial lookup.

## CHECKCERTANDCLUE (two handlers, method-dependent)

This command has **two** handlers in the binary and the reproduction matches
both (verified live, all forms):

`POST` (body = Base64 certificate, handler 0x464110) — checks whether the
posted certificate's private key ("clue" / ключ) is in the local store:

| Body | Response |
|---|---|
| valid cert, key in store | `{"Status":true,"Data":null,"Errors":[]}` |
| valid cert, no key in store | `Status:false, ["ключевой носитель не найден"]` (lower-case к) |
| not a certificate / empty | `Status:false, ["Переданные данные не являются сертификатом безопасности"]` |

`GET` (handler 0x467ca0) — looks the certificate up by `CertSN`/`CertThumb`:

| Params | Response |
|---|---|
| found, key present | `{"Status":true,"Data":null,"Errors":[]}` |
| not found (incl. empty value — presence, not value, is checked) | `Status:false, ["Сертификат не найден"]` |
| found, no key | `Status:false, ["Ключевой носитель не найден"]` (upper-case К) |
| no `CertSN`/`CertThumb` param at all | `Status:false, ["Не указан SN (или Thumbprint) сертификата"]` |

The web client uses the POST form (it posts the certificate and expects the
key check), which an earlier revision got wrong by only implementing the GET
lookup.

## Deliberate deviations (the original 2.7.0.9 is broken here)

This build crashes (`EAccessViolation`, "AccessViolation,killing thread")
on several paths; the reproduction returns the message recovered from the
disassembly instead of crashing:

| Command | Original 2.7.0.9 | Reproduction |
|---|---|---|
| `GETLOGINFO` (any form) | `200` body `#Error#EAccessViolation Access violation` | task list JSON (`GETLOGINFO` serializer, recovered) |
| `GETRESULT?Id=<missing>` | `#Error#EAccessViolation …` | `Status:false, ["Криптозадание с Id=X не найдено"]` |
| `GETSIGN` **async** (any) | `#Error#EAccessViolation …` (the async queue path faults) | task id, then `GETRESULT` returns the result |
| sync error paths (`GETSIGN_SYNC` без SN, bad thumb/SN, `SIGN_SEDO_REQUEST` без fss/SN) | sends `Content-Length` but an **empty body** (truncated) | full `Status:false … Errors:[…]` JSON with the recovered message |

The async crash means the original effectively only works `_SYNC`; the
reproduction implements the async `CRYPTO_TASKS` flow the binary intended.

## Not reproducible without fixtures

`SIGN_SEDO_REQUEST` / `SIGN_POVED_REQUEST` (empty body on the original for a
plain document — they expect a specific SEDO/POVED XML envelope) and
`DECRYPT_SEDO_RESPONSE` (original: `Ошибка чтения зашифрованного xml
документа …` for a raw CMS — it expects an XML wrapper). `GET_XML_SIGN`
returns `Ошибка выполнения криптозадачи` on the original for arbitrary XML.
These proprietary transformations are left unimplemented (they fail with a
clear message) pending real request/response captures.

## CMS structure

`openssl asn1parse` on an original detached signature vs. ours (same key):
identical except the signing-time `UTCTIME` and the signature `OCTET
STRING` (both expected to differ per signature). The original does **not**
add signed attributes for a bare `GETSIGN`; the pycades `SignCades(PKCS7)`
path adds `signingTime`/`contentType`/`messageDigest`. Both verify.
