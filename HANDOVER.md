# Handover: StekTrustPlugin Python Reproduction

## Objective

Decompile and reproduce the Linux plugin distributed at
`https://www.stek74.ru/uploads/files/Plugin/stek.plugin.tar` in Python.
Hard requirement from the user: **do not implement GOST, CMS, ASN.1 or
XML-DSig primitives here** — use CryptoPro CSP or another proven
implementation.

## Current Status (2026-08-25)

Protocol reproduction is now based on a complete trace of the HTTP command
handler in the binary; the CryptoPro adapter is verified against the CSP
installed on this host (CryptCP 5.0 / Certmgr 1.1, CSP 5.0 R2, three GOST
certificates on a Rutoken Lite).

Done and tested (32 tests, `python -m unittest discover -s tests -t . -v`):

- Envelope, status codes and messages for every command (see README table).
- `#Error# <message>` text framing for exceptions / unknown commands.
- Base64 document decoding (0xa9ac00) and Base64 `Data` encoding (0xa9a9b0).
- Task-id generator format (31 lowercase hex, verified against sample DB).
- SQLite layout compatible with the original file (Julian-day timestamps).
- `GETLOGINFO` task-list serializer, `GETLOGFILE`, `GETRESULT` states.
- CORS headers and `Server: TRUST` over a real socket.
- `certmgr -list` parsing, DER export, certmgr-style Subject/Issuer strings,
  `inn` / `onlyValid` filters; live enumeration passes on this host.
- `cryptcp -sign` / `-decr` command lines verified with `-help` output.

Not yet verified:

- Live signing verified 2026-08-25 (PIN was cached on the token): cryptcp
  detached/attached CMS, pycades detached/attached CMS (both verified with
  `cryptcp -verify`, attached content recovered), `SIGN_HASH` raw 64-byte
  signature, and the HTTP round trip `GETSIGN_SYNC` / `SIGN_HASH_SYNC` /
  `GETLOGINFO` through the pycades default backend.
- `SIGN_HASH` byte order verified: a `csptest -keyset -keytype exchange
  -sign GOST12_256` signature (raw CryptSignHash output) passes
  `RawSignature.VerifyHash` unreversed, so pycades returns the CryptSignHash
  order and the backend passes it through (`RAW_SIGNATURE_REVERSED=False`).
- Decrypt (`cryptcp -decr` / `EnvelopedData.Decrypt`) untested for lack of
  an encrypted fixture (`cryptcp -encr -thumbprint T in out` would make one).
- pycades runs in-process without a timeout: an unanswered CSP PIN dialog
  blocks the backend. `default_backend()` therefore picks pycades only when
  a PIN is configured or a display is present; otherwise cryptcp (600 s
  timeout). PIN is applied via `Signer.KeyPin` and `PrivateKey.KeyPin`.
- `SignCades(CADESCOM_PKCS7_TYPE)` output is CAPICOM-style SignedData
  (signed attributes); not byte-identical to `CryptSignMessage`/cryptcp.
- `certmgr` is run with `LC_ALL=C.UTF-8`; whether it honours it on a
  `ru_RU` system is not yet checked live.
- pycades signing/decrypt paths (`SignedData.SignCades(PKCS7_TYPE)`,
  `EnvelopedData.Decrypt`) are verified only against a fake module.
- `GET_XML_SIGN`, SEDO/POVED envelope transformations: not reconstructed.
- `TRYUSEPLUGIN`/`PING` read a start-up global string in the original whose
  origin was not traced (only `Status` matters to clients).
- Indy's exact rule for `UnparsedParams` vs `FormParams` was not confirmed
  from source; the server accepts query-string params with a raw Base64 body
  (the expected client form) and also form-encoded bodies carrying known keys.

## pycades (built 2026-08-25)

`pycades` 0.1.70193 is installed in `~/.local/lib/python3.14/site-packages/pycades.so`
(works with both brew `python3` and `/usr/bin/python3`, no libpython link).
Built without root from `pycades.zip` + the headers of
`~/Downloads/bs/архив 23.02/linux-amd64_deb/lsb-cprocsp-devel_5.0.12000-6_all.deb`
extracted to a temp dir; recipe and patches in `tools/pycades/` (build.sh,
CMakeLists.txt, stub/cpcsp/visibility.h). Gotchas: the 2.0.15700 cades headers
need `cpcsp/visibility.h` (`CPRO_PUBLIC_API`, `NS_SHARED_PTR`) from a newer
devel package — stubbed; libcppcades exports `std::shared_ptr`, so the
boost::shared_ptr in the pycades sources is sed-replaced; the SAL macro
`__out` from CSP_WinDef.h breaks `<algorithm>` unless STL headers are
force-included first; `libcplib` must be linked for `CryptoPro::CBlob`.
`Store.Certificates` shows 4 certificates (certmgr lists 3).

## Golden comparison (2026-08-25, full parity)

A request-by-request diff harness now compares the running original against
the reproduction across all 25 command forms — 0 mismatches. Two correctness
bugs this caught and fixed after the first pass:
- **RDN order was reversed.** The original prints Subject/Issuer in native DER
  order (Subject OGRNIP..SN, Issuer INNLE..CN); `rdn_pairs` had a stray
  `reversed()`. Both strings were backwards. Fixed (no reverse).
- **ENUMCERTS "qualified" filter.** ENUMCERTS/ENUMALLCERTS list only certs
  whose subject has a Russian ID OID (INN/INNLE/OGRN/OGRNIP/SNILS); a keyed
  self-signed CN=mykey cert is excluded from enumeration but still found by
  lookup. Implemented as `Certificate.qualified` + `qualified_only` (enum
  only). See GOLDEN.md.
Also: `Plugin.handle` now upper-cases the command (the client uses mixed case
like `GetVer`; the HTTP layer already upper-cased, this hardens direct callers).

## Golden comparison (first pass, 2026-08-25)

The original binary was run live (see GOLDEN.md). Findings folded into the
code: ENUMCERTS = all private-key certs / ENUMALLCERTS = valid-only (they
were backwards); TRYUSEPLUGIN & CHECKCERTANDCLUE return `Data:null`; OPTIONS
returns the Indy HTML 200 body with `text/html`; exception text is
`#Error#<ClassName> <msg>`; RDN keys `GN=`/`streetAddress=`, no quoting;
Serial/Thumbprint upper-case; headers `application/json; charset=utf-8` +
`Content-Encoding: utf-8`. The original 2.7.0.9 **crashes** (EAccessViolation)
on GETLOGINFO, GETRESULT-for-missing-task and all async signing, and truncates
sync error bodies; the reproduction returns the intended messages instead
(documented in GOLDEN.md). Golden captures: scratchpad `fixtures/`.

## Environment note (2026-08-25)

Mid-session the host CSP was upgraded 5.0.12000 -> 5.0.13800. On 5.0.13800
the CAdES SDK (cprocsp-pki-cades 2.0.15700) still references
`CryptoPro::CBlob::pbData()` (`_ZNK9CryptoPro5CBlob6pbDataEv`), which the base
CSP no longer exports — it now ships in **`cprocsp-legacy-64`**
(`libcplib.so.4`). So on 13800+, pycades needs `cprocsp-pki-cades-64` **and**
`cprocsp-legacy-64` installed. Verified: with libcplib.so.4 present, the
rebuilt pycades imports and signs (SIGN_HASH 64 B, detached CMS verified).
`default_backend()` falls back to cryptcp automatically when pycades is
unimportable, so only `SIGN_HASH` is affected. The build recipe
(`tools/pycades/CMakeLists.txt`) now links whichever CBlob-providing libs
exist (`cplib`/`cpasn1`/`cades`/`cppcades`) across CSP versions.

Package dependencies for both backends are declared in `debian/control`
(Depends: lsb-cprocsp-capilite-64 for cryptcp/certmgr + kc1 provider;
Recommends: cprocsp-pki-cades-64, cprocsp-legacy-64 for pycades).

## Code review (2026-08-25)

A review agent audited the tree; fixes applied: form-encoded body document
rule (`Data=<b64>` value, or bare body; never a known parameter), hex
validation of `CertThumb`/`CertSN` before they reach argv, `TaskDB.cleanup()`
at start-up and hourly (7-day blob / 30-day row purge as in the original),
`certmgr` run with `LC_ALL=C.UTF-8` + parse warning, 5 s store-list cache and
DER cache, one CSP operation at a time (lock), worker survives DB close,
`Content-Length`/chunked/oversize guards (400/411/413), rotating log,
live tests opt-in via `STEK_LIVE=1`, local-time validity dates, INN filter by
exact match, `RotatingFileHandler`, start-up warning when a PIN is supplied.

Accepted as inherited from the original (documented, not changed):
- CORS `*` — any page can drive the plugin; the CSP PIN dialog is the only
  per-operation consent. A stored PIN (`--pin`/`STEK_CSP_PIN`) removes it.
- `+` inside a form-encoded Base64 value becomes a space and is dropped by
  the lenient decoder — same as Indy `URLDecode` + 0xa9ac00; clients must
  URL-encode the document or send it as a raw body.
- `GETLOGFILE`/`GETLOGINFO` expose the log and task history to any origin.
- Duplicate client `TaskId` -> `#Error# UNIQUE constraint failed ...`
  (the original raises the SQL exception the same way).

## Workspace

Project: `/home/boger/work/board/tmp/moedelo/stek_plugin_py` (not a git repo).

Extracted artifacts (re-download if `/tmp/opencode` is gone):

- `/tmp/opencode/stek.plugin.tar`, `/tmp/opencode/stek_plugin/`, `/tmp/opencode/stek_deb/`
- binary: `/tmp/opencode/stek_deb/usr/share/stek.plugin/StekTrustPlugin`
- sample DB: `/tmp/opencode/stek_deb/usr/share/stek.plugin/StekTrustPlugin.gdb`
- analysis: `/tmp/opencode/analysis/` — `strings.txt`, `full.asm`
  (`objdump -d -M intel`), `annot.py <lo> <hi>` (prints a range with string
  literals resolved), plus per-handler dumps (`serializer.asm`,
  `getsign_handler.asm`, `sync_tail.asm`, `crypto_handler.asm`, ...).

## Key Addresses (all confirmed this session)

| What | Address |
|---|---|
| HTTP handler prologue: CORS headers, JSON content type | 0x468349–0x4683df |
| POST dispatcher (`_SYNC` strip, command match) | 0x4685a0–0x4688d5 |
| Exception → `#Error# `+msg | 0x468c03 (POST), 0x469a03 (GET) |
| Unreachable `#OK#` / octet-stream branch | 0x468a59–0x468af2 |
| JSON builder scalar (`Data` Base64 unless r9b=1) | 0x462e70 |
| JSON builder array | 0x4632d0 |
| Base64 encode / decode | 0xa9a9b0 / 0xa9ac00 |
| GETSIGN handler (params, TCryptoTask, async/sync) | 0x4650d0 |
| Sync executor (200 for both success and error JSON) | 0x463800 |
| SEDO/POVED handler | 0x464bf0 |
| DECRYPT handler (no SN check) | 0x465520 |
| DECRYPT_*_RESPONSE handler | 0x464770 |
| GETRESULT handler (default 401; 201/200/500) | 0x466cb0, lookup 0x4705c0 |
| GETLOGINFO serializer | 0x467010 |
| GETLOGFILE | 0x466aa0 |
| ENUMCERTS handler | 0x4658f0 |
| GETCERTBODY / CHECKCERTANDCLUE (GET) | 0x463c30 / 0x467ca0 |
| PING / GETVER handlers | 0x4669c0 / 0x466920 |
| Task id: GUID → reversed groups, 31 chars | 0xa99d40 + LowerCase 0x4d7350 |
| CertSN normalisation (strip ':' and ' ') | 0x46c170 |
| OID→RDN name table | .rodata 0xb08440–0xb09220 |

## Task Types / Statuses

`TTYPE`: 0 DetachedSign, 1 AttachedSign, 2 XMLDsig, 3 BuildPOVEDRequest,
4 BuildSEDORequest, 5 Decrypt, 6 DecryptFssResponse (used by
`DECRYPT_POVED_RESPONSE`), 7 (no name; `DECRYPT_SEDO_RESPONSE` and
`DECRYPT_FSS_RESPONSE`), 8 SignHash. Keep this odd mapping; it is copied
from the dispatcher. `STATUS`: 0 New, 1 Wait, 2 Success, 3 Error.

## CryptoPro CLI Facts (this host)

- `cryptcp -sign <CSC> [-nochain] [-der] [-detached|-attached] [-pin P] in out`
  — `-signf` writes `in.sgn` next to the source and omits the certificate by
  default; do not use it.
- No serial selector: only `-thumbprint` / `-dn`; serials are resolved via
  `certmgr -list` first.
- `cryptcp -decr [<CSC>] [-pin P] in out`.
- `certmgr -export -thumbprint T -dest f` writes DER; `-list` prints
  `N-------` blocks with `SHA1 Thumbprint`, `Serial : 0x…`,
  `PrivateKey Link : Yes`.
- `cryptography` 49 parses GOST certificates (`public_key()` raises, which is
  fine; only names/dates/serial/fingerprint are used).
- Subject strings: CryptoAPI order (reversed DER), keys `OGRNIP, SNILS, INN,
  INNLE, OGRN, C, S, L, O, CN, G, SN, E, STREET, T, OU, unstructuredName`.

## Project Files

- `stek_plugin/__init__.py` — constants, messages, OID table.
- `stek_plugin/server.py` — `Plugin.handle(method, command, params, body)`,
  HTTP handler, CORS.
- `stek_plugin/taskdb.py` — SQLite queue, worker, task id generator, Julian
  timestamps.
- `stek_plugin/responses.py` — envelope/record builders (`json.dumps`).
- `stek_plugin/params.py` — query/form parameter access.
- `stek_plugin/backends/base.py` — `Certificate`, `CryptoBackend`, serial
  normalisation.
- `stek_plugin/backends/csp.py` — CryptoPro adapter (`cryptcp`/`certmgr`) and
  the shared `certificate_from_der` / name formatting.
- `stek_plugin/backends/pycades_backend.py` — official-binding adapter
  (default when importable); `backends.default_backend()` picks.
- `tools/pycades/` — reproducible pycades build.
- `tests/test_protocol.py`, `tests/test_http.py`, `tests/test_csp_backend.py`,
  `tests/test_live_csp.py`.

## Next Steps

1. (done) Live signing verified for both backends.
2. Test decryption with a message encrypted for one of the store certificates
   (`cryptcp -encr -thumbprint T in out`).
3. (done) `SIGN_HASH` byte order verified against CryptSignHash via csptest.
4. Capture real browser requests to the original plugin (Windows build or a
   VM) to confirm the body/parameter conventions and to obtain SEDO/POVED
   fixtures before attempting those transformations.
5. Optional: tray/GUI is out of scope; the original also keeps a session
   "update" loop (0x468960) with no protocol effect.

## Engineering Constraints

- Never implement GOST/CMS/ASN.1/XML-DSig manually.
- Use `json.dumps`; do not hand-build JSON.
- Preserve the recovered task-type mapping and messages byte-for-byte.
- Keep the server bound to localhost by default.
