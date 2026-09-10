# Стэк.Плагин

Локальная HTTP-служба (`127.0.0.1:18080`, префикс `/TRUST/`), совместимая с
`StekTrustPlugin 2.7.0.9`: браузер вызывает её для подписи и расшифрования
через КриптоПро CSP. Своей криптографии нет — всё делегируется КриптоПро
(pycades или `cryptcp`/`certmgr`), X.509 разбирается библиотекой `cryptography`.

Работает и с онлайн-бухгалтерией **«Моё дело»** — заменяет
**МоёДело.Плагин для Linux**.

## Зависимости

Пакеты КриптоПро ставятся отдельно (не из Debian). Скачать (нужна бесплатная
регистрация на cryptopro.ru):

- **КриптоПро CSP** (архив `linux-amd64_deb.tgz`) — даёт `lsb-cprocsp-*`,
  провайдер KC1, читатели носителей и `cprocsp-legacy-64`:
  <https://www.cryptopro.ru/products/csp/downloads>
- **КриптоПро ЭЦП SDK** — `cprocsp-pki-cades-64` (нужен только для pycades;
  в CSP 5.0 R3 / 5.0.12900+ уже входит в дистрибутив CSP):
  <https://www.cryptopro.ru/products/cades/downloads>
- **pycades** (исходники модуля Python) — собирается через
  `tools/pycades/build.sh`:
  <https://cryptopro.ru/sites/default/files/products/cades/pycades/pycades.zip>

Подробнее — `debian/control` и `debian/README.Debian`.

| Пакет | Зачем |
|---|---|
| `lsb-cprocsp-base`, `lsb-cprocsp-capilite-64` | рантайм, `cryptcp`/`certmgr`, `libcapi*` |
| `lsb-cprocsp-kc1-64`, `lsb-cprocsp-rdr-64` | GOST-провайдер KC1, поддержка носителей |
| `cprocsp-pki-cades-64`, `cprocsp-legacy-64` | для backend pycades (`libcades`/`libcppcades`, `libcplib.so.4`) |
| `cprocsp-rdr-pcsc-64`, `cprocsp-rdr-rutoken-64`, `ifd-rutokens`, `pcscd` | токен Rutoken |
| `python3-cryptography` (≥42) | разбор X.509 |

Сертификат с закрытым ключом должен быть в пользовательском хранилище `My`.

## Запуск

```bash
python -m stek_plugin [--host 127.0.0.1] [--port 18080] [--backend auto] \
                      [--pin PIN] [--db :memory:] [--log -]
```

Примеры:

```bash
curl http://127.0.0.1:18080/TRUST/PING
curl 'http://127.0.0.1:18080/TRUST/ENUMCERTS?onlyValid=true'
base64 -w0 doc.xml | curl -X POST --data-binary @- \
  'http://127.0.0.1:18080/TRUST/GETSIGN_SYNC?CertThumb=ОТПЕЧАТОК'
```

## Backend (`--backend auto|pycades|cryptcp`)

- **pycades** — официальная привязка КриптоПро (предпочтительно; даёт
  `SIGN_HASH`, без временных файлов). Не в PyPI: собрать через
  `tools/pycades/build.sh` из `pycades.zip` и `lsb-cprocsp-devel` вашей версии
  CSP. Требует `cprocsp-pki-cades-64` **и** `cprocsp-legacy-64`; если импорт
  падает с `_ZNK9CryptoPro5CBlob6pbDataEv` — доставьте `cprocsp-legacy-64`.
- **cryptcp + certmgr** — запасной вариант (без `SIGN_HASH`).

`auto` берёт pycades, если он импортируется и задан PIN либо есть дисплей;
иначе `cryptcp`.

## Один экземпляр на машину

Служба слушает `127.0.0.1:18080` — loopback общий для всей машины, поэтому
порт может занять только **один** процесс (как и оригинальный плагин, и любой
подобный: КриптоПро CAdES, МоёДело и т. п. используют свои порты). Первый
запущенный экземпляр обслуживает все локальные запросы; остальные (другая
сессия, повторный запуск, ещё работающий оригинальный `StekTrustPlugin`)
видят занятый порт, пишут предупреждение и **завершаются с кодом 0** — без
цикла перезапуска. То есть не запускайте его параллельно с оригиналом (он его
и заменяет). Экземпляр работает в сессии одного пользователя и использует его
ключи — на обычной однопользовательской машине это ровно один процесс.

## systemd

Служба использует ключи пользователя (токен через `pcscd` или контейнер в
профиле), поэтому это **пользовательский** юнит. Пакет включает его
(`systemctl --global enable`) — он стартует при следующем входе в систему.
Запустить сразу в текущей сессии:

```bash
systemctl --user start stek-plugin
systemctl --user status stek-plugin
journalctl --user -u stek-plugin -f
```

Юнит запускает `stek-plugin --log -` (лог в journald). PIN для автономной
работы — в drop-in
(`systemctl --user edit stek-plugin`, `Environment=STEK_CSP_PIN=…`); учтите,
что сохранённый PIN даёт любой странице подписывать без запроса.

## Debian-пакет

```bash
dpkg-buildpackage -us -uc -b
```

## Тесты

```bash
python -m unittest discover -s tests -t . -v
```

Протокол/HTTP — на фейковом backend; живые тесты (реальный CSP) — только с
`STEK_LIVE=1` (подпись дополнительно `STEK_LIVE_SIGN=<отпечаток>`,
`STEK_CSP_PIN`).

## Лицензия

MIT — см. [LICENSE](LICENSE). Код КриптоПро не включён; КриптоПро CSP
лицензируется отдельно.
