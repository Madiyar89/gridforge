# GridForge — справка: что сделано, что проверено, что осталось

Репозиторий: `github.com/Madiyar89/gridforge` (приватный, ветка `master`).
Обновлено: **2026-09-25**, эта сводка обновляется вручную и может
отставать — сверяйся с `git log`, если прошло много времени. Подробности
по каждой фиче и командам `curl` — в [README.md](README.md); построчная
история "что сделано, как проверено вживую, какие баги нашёл живой
прогон" по каждому пункту — в [docs/PROGRESS_LOG.md](docs/PROGRESS_LOG.md)
(не здесь — эта сводка короткая специально). Практическое «как
пользоваться сайтом» (не для разработчика) — [ИНСТРУКЦИЯ.md](ИНСТРУКЦИЯ.md).

## 1. Что это

Собственная система сетевого мониторинга/управления, написанная **с
нуля**. Zabbix 6.0 (GPLv2) и NetOpsHub (тот же владелец, другой продукт)
использовались только как источники идей — ни код, ни схема БД, ни
формат протокола не копировались; переносимый функционал переписывается
заново, под своей терминологией (см. §7 и `app/models.py`). Цель — продукт,
который в перспективе можно продавать как закрытый.

Стек: Python (venv в `venv/`, актуальная версия — смотри
`venv/pyvenv.cfg`), FastAPI, SQLAlchemy (SQLite по умолчанию, MySQL/
MariaDB через `GRIDFORGE_DATABASE_URL`), asyncio. Фронтенд — vanilla
HTML/CSS/JS без сборки, 30 отдельных страниц (`static/*.html` + одноимённый
`.js`, общее — `common.js`/`style.css`/`vendor/xterm`).

## 2. Быстрый старт

```bash
cd gridforge
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8100
```

### Постоянная работа (systemd)

```bash
sudo cp deploy/gridforge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gridforge
systemctl status gridforge
journalctl -u gridforge -f
```

Не `uvicorn` руками в фоне — такой процесс не переживает перезагрузку и
теряет лог из `/tmp`. Работает не от root: syslog слушает 5140, NetFlow —
2055 (оба непривилегированные, не 514/тот же принцип).

### Вход в интерфейс

`http://<адрес сервера>:8100/` → логин **`Admin`**, пароль **`gridforge`**
(учётка заводится сама при первом старте).

> **СМЕНИТЬ ПАРОЛЬ ПРИ РАЗВЁРТЫВАНИИ.** Пока не сменён — GridForge
> предупреждает в лог при каждом старте и показывает баннер в
> интерфейсе. На момент этой сводки на инстансе, с которого она писалась,
> пароль **всё ещё дефолтный** — сменить в первую очередь.

Способы входа:
- **Логин/пароль** — локальная учётка или **AD** (`app/ad_auth.py`,
  `GRIDFORGE_AD_SERVER`/`_DOMAIN`/`_DEFAULT_ROLE`/`_VERIFY_CERT`).
- **OIDC SSO** (`app/oidc_auth.py`, §3.9) — кнопка на `login.html`
  появляется, только если настроен.
- **API-ключ** в заголовке `X-API-Key` — для программ/интеграций.
  Первый ключ печатается в консоль один раз при самом первом старте
  (в БД — только SHA-256 хеш) и дублируется в
  `data/BOOTSTRAP_ADMIN_KEY_DELETE_ME.txt`.

Три роли (одинаковы для ключей и пользователей): `viewer` (только
чтение), `operator` (+ запуск операций на оборудовании: бэкап, аудит,
скан, захват трафика), `admin` (+ инвентарь/правила/каналы/выдача
ключей). Ключ/пользователя можно дополнительно ограничить одной группой
узлов (`key_sees_group()` в `app/auth.py` — единая точка проверки).

- Данные — в `data/` (SQLite `gridforge.db`, `secret.key` для шифрования
  секретов, `geoip/*.mmdb`, pcap-файлы, bootstrap-ключ). В `.gitignore`,
  **потеря `secret.key` = потеря всех сохранённых паролей/токенов**.
- Миграции схемы — ручные (`app/db.py`): `_migrate_missing_columns()`
  (`ALTER TABLE ... ADD COLUMN`) и `_migrate_renamed_columns()`
  (`RENAME COLUMN`, для случаев вроде переименования `dc_host`→
  `dc_address`, см. §5). `Base.metadata.create_all()` создаёт только
  отсутствующие **таблицы**, не колонки.

## 3. Что сделано

### 3.1 Ядро мониторинга
Планировщик на мин-куче, один asyncio-цикл (`scheduler.py`, не форк-модель
Zabbix). Проверки (`probes.py`, реестр по `ProbeKind`): `icmp_ping`,
`tcp_port`, `ssh_command`, `snmp_get` (v1/v2c/**v3 USM**), `snmp_walk`,
`snmp_counter_rate` (со скоростью и переполнением счётчика, `rate_engine.py`).
`Watch` → `Incident` с дедупом (`watch_engine.py`). Уведомления —
`webhook`/`telegram`/**`apprise`** (80+ сервисов одной библиотекой,
`signal.py`), многоступенчатая эскалация (`escalation_engine.py`).
Действия по инциденту — SSH-команда (`actions_engine.py`). Шаблоны
мониторинга — наборы Probe+Watch одним применением (`templates_engine.py`).

### 3.2 Перенесено из NetOpsHub (переписано, не скопировано)
Инвентарь (`Group`/`Node.vendor`), бэкапы по SSH + unified diff (в
SQLite, без git), аудит конфигураций, AD-аудит в духе PingCastle
(`ad_audit_engine.py`/`ad_audit_collector.py`/`ad_audit_rules.py`), аудит
сетевых конфигураций Cisco/Junos с риск-скором (`network_audit_*.py`),
скан сети (nmap), SSH-консоль в браузере (`console_ws.py` + xterm.js),
приём Syslog, захват/анализ трафика (tshark/dumpcap), IP-поиск
hostname/пользователя, доменная инвентаризация WinRM/SMB
(`domain_scan_engine.py`), поиск MAC по всему парку, вероятные
хабы/неуправляемые свитчи (`hub_detection_engine.py`), Compliance-правила
по парку, поиск по конфигам (grep), справочник команд по вендорам,
хранилище образов ПО, Сценарии (массовая правка конфига,
`scenarios_engine.py`), централизованные учётки (`Credential`,
`credentials_engine.py`), Port Security/STP-защита
(`port_security.py`/`stp_protection.py`), состояние портов + живые
MAC/up-down (`ports_engine.py`), журнал кабельных соединений с
**CDP-автоопросом по расписанию** (`cable_discovery_engine.py`), проверка
на уязвимости с накопительным Excel-реестром и плановым запуском
(`vuln_scan_engine.py`/`vuln_register.py`), Telnet-транспорт для старых
коммутаторов (`telnet_client.py`), массовый прогон команд по группе
(`sweep_engine.py`).

### 3.3 Из обзора 8 open-source проектов (`docs/landscape-report.md`) — 7 из 10
Отсортировано по номеру пункта в отчёте:
- **4.1** Фоновый скан → Incident/Signal на новое устройство в сети.
- **4.2** Канал уведомлений через **Apprise** (`ChannelKind.apprise`).
- **4.3** `/metrics` для Prometheus.
- **4.4** **GeoIP/ASN** для внешних адресов (`app/geoip_engine.py`) —
  офлайн-базы MaxMind GeoLite2, ключ через Integration, автообновление
  раз в ~7 дней, панель поиска на `syslog.html`.
- **4.5** Приёмник **NetFlow v9** (`app/netflow_server.py`, порт 2055) +
  дашборд топ-трафика (`flows.html`) — не sFlow/IPFIX, сознательно узкий
  старт. Доработка 2026-09-26: Node-имена в API, топ протоколов,
  пороговые оповещения `FlowAlertRule` (`app/flow_alerts_engine.py`),
  очистка кэша шаблонов. Детали — `docs/PROGRESS_LOG.md`.
- **4.6** Правила жизненного цикла устройств (`app/lifecycle_engine.py`)
  — автогруппировка по вендору + «офлайн N дней → архивировать?»,
  подсказки на `inventory.html`, без новой таблицы под находки.
- **4.8** **OIDC SSO** (`app/oidc_auth.py`) — любой провайдер со
  стандартным Discovery, отдельно от AD.
- **4.9** **«Спроси про сеть»** (`app/ask_engine.py`) — read-only
  ИИ-агент на Gemini, физически read-only SQL-доступ (не на слове
  промпта), `ask.html`.
- **4.10** Sync Node/мульти-сайт — **шаг 2 из 5** сделан:
  `app/sync_engine.py`, площадка сама шлёт JSON-снимок на хаб по
  расписанию, страница `sync.html`. Шаги 3-5 не начаты. Детали —
  `docs/PROGRESS_LOG.md`.

Не сделано: **4.7** (LLDP для не-Cisco — ждёт реального доступа к
Juniper-парку, см. §4).

### 3.3b Внешние security-инструменты (обсуждение с владельцем 2026-09-25)
- **Nuclei** — профиль `VulnScanProfile.nuclei` в Проверке на уязвимости.
- **Feroxbuster** — профиль `VulnScanProfile.web_discovery`.
- **NetExec → CredentialCheckRun** — узкий срез (только проверка
  SMB-логина, без выполнения команд) напрямую через `impacket`, не сам
  NetExec (почему — см. `docs/PROGRESS_LOG.md`).
  `app/credential_check_engine.py`, страница `credential-check.html`.

Все три проверены вживую 2026-09-25, детали и найденные живым прогоном
баги — `docs/PROGRESS_LOG.md`.

### 3.4 Веб-интерфейс
30 страниц (`static/*.html`): Дашборд, Инвентарь (+ подсказки
жизненного цикла), Шаблоны, Рубка, Сценарии, Порты, Консоль, Команды,
Версии ПО, Бэкапы, Аудит, Поиск по конфигу, Вероятные хабы, Поиск MAC,
Домен, Syslog (+ GeoIP-поиск), Скан, Уязвимости, Кабели, Трафик,
Потоки (NetFlow), AD-аудит, Аудит сети, **Спроси про сеть**, Каналы (+
эскалация), Пользователи, Учётки, Интеграции, LDAP. Общая шапка/навигация
— `common.js` (аккордеон-группы, закрепление рельсы, индикатор роли).

## 4. Что осталось

1. **4.7 LLDP как второй источник журнала кабелей** — заблокировано на
   реальный вывод команды с живого оборудования (сознательно: один раз
   уже ловили баг парсера CDP, написанного «по памяти»). План
   согласован с владельцем: тестировать на **Cisco IOS** (`show lldp
   neighbors detail` — Cisco тоже умеет LLDP, не только CDP), не на
   Juniper (тот локально не поднять, проприетарная ОС). Нужны:
   Credential (логин/пароль) на реальный узел тестового парка
   (`LAB-1` и другие, несколько подсетей, 56 узлов уже заведено) —
   сеть с этой машины сейчас недоступна (роутинг с этой VM туда не
   идёт), ждём доступа/подтверждения от владельца.
2. **4.10 Sync Node / мульти-сайт** — крупная архитектурная задача,
   годы вперёд, не начинать без конкретного MSP-сценария.
3. **Сменить пароль Admin** на этом инстансе (см. §2) — до сих пор
   дефолтный.
4. **Убрать использованные sudoers-гранты**, если ещё актуальны:
   `/etc/sudoers.d/claude-zabbix-install` (Zabbix полностью удалён с
   этой машины 2026-09-25 — файл уже мёртвый груз) и
   `/etc/sudoers.d/claude-samba-install` (тестовый AD DC, сервис сейчас
   остановлен). Не удалялись автоматически — решение владельца.
5. Индикатор роли в топбаре (`updateRolePill()`, `common.js`) не
   обновляется визуально при входе через cookie-сессию (локальный
   пароль/AD/OIDC) — завязан только на `localStorage`-ключ. Сама
   авторизация работает исправно (проверено вживую), это чисто
   косметический пробел в топбаре, не исправлялся — вне рамок задач,
   где был обнаружен.
6. Не перенесено из NetOpsHub (нужна внешняя инфраструктура, которой не
   было под рукой на момент разработки): интеграция с Graylog как
   отдельным сервисом (сам GridForge теперь заменяет часть этой задачи
   собственным syslog+IP-поиском), ESXi-инвентарь, Firepower/PAN-OS
   API, RDP через браузер (Guacamole-аналог — SSH-консоль сделана, RDP
   не делали, отдельный сложный бинарный протокол).
7. Автотестов (`tests/`) — 40+, но не на каждый модуль; фичи
   §3.3/§3.4 проверялись вживую (см. §5), а не юнит-тестами — при
   правке этих модулей в первую очередь перепроверять вручную, не
   полагаться только на `pytest`.

## 5. Как проверялось (дисциплина этого проекта)

Каждая фича — не только компиляцией/юнит-тестом, а вживую на реальной
инфраструктуре, обычно на изолированной копии (`/tmp/gridforge-*-test`,
свой порт/`GRIDFORGE_SYSLOG_PORT`/`GRIDFORGE_NETFLOW_PORT`, отдельная
`data/`), с уборкой за собой:
- Реальный SSH/Telnet, SNMPv1/v2c/**v3**-агент, поднятый **Samba4 AD
  DC** с реалистичными уязвимыми тестовыми аккаунтами.
- Реальные `nmap`/`tshark`/`dumpcap` на настоящем трафике.
- Реальные UDP-пакеты: syslog (`nc -u`), **NetFlow v9** (собран по
  спецификации Cisco вручную — Template+Data FlowSet, шаблоны
  кэшируются между пакетами).
- Реальные внешние сервисы: **MaxMind GeoLite2** (настоящий ключ,
  8.8.8.8→US/Google подтверждено), **ntfy.sh** (Apprise-доставка),
  **Keycloak** (полноценный Docker-контейнер, свой realm/client/
  пользователь через admin REST API — весь OAuth2/OIDC-цикл
  Authorization Code + PKCE вживую через headless Chromium), **Gemini**
  (настоящий ключ, ответы сверены с прямым SQL-запросом к копии боевой
  БД, промпт-инъекция `DELETE FROM nodes` отбита и моделью, и —
  отдельно, в обход модели — обоими слоями read-only-защиты).
- Клики в браузере — **headless Chromium через CDP** (raw
  `websocket-client`), не только curl: логин-форма, панели, кнопки
  «применить».

Юнит-тесты (`pytest`, venv напрямую — на этой машине НЕ виснет, в
отличие от WSL-копии, см. CLAUDE.md) гоняются как регрессия перед
каждым деплоем: `test_naming_purity`, `test_api_channels`,
`test_channel_secrets`, `test_signal_dispatch`, `test_api_auth` — набор
подбирается по теме правки, полный прогон не обязателен для мелких
изменений.

## 6. Известные ограничения и подводные камни

- `known_hosts` для SSH по умолчанию **не проверяется** — для боевой
  сети задать явно в `params.known_hosts`.
- LDAP-подключение AD-аудита — `CERT_NONE` (самоподписанные
  сертификаты лабораторных доменов); **вход через AD/OIDC**, наоборот,
  по умолчанию проверяет сертификат — там по сети идёт реальный пароль
  человека, не только чтение атрибутов.
- Захват трафика видит только интерфейсы этой машины, не mirror-порт
  коммутатора (физическая топология, не софт).
- `str(asyncio.TimeoutError())` — пустая строка; код вида `detail or
  fallback` на таймауте молча теряет текст ошибки — уже исправлено в
  местах, где ловили, не повторять в новых.
- Второй экземпляр на одной машине: разный `--port`, разный
  `GRIDFORGE_SYSLOG_PORT` **и** `GRIDFORGE_NETFLOW_PORT` (иначе конфликт
  с уже слушающим боевым `gridforge.service` — реальный инцидент
  2026-09-25, поймано тестами, см. `tests/conftest.py`), отдельная
  `data/`.
- Переименование колонки БД — не `ADD COLUMN`, а `RENAME COLUMN`
  (`app/db.py:_migrate_renamed_columns()`), иначе на живой БД получится
  вторая пустая колонка вместо переименования старой.
- `pysnmp` пишет `CryptographyDeprecationWarning` про CFB-режим AES при
  SNMPv3 — безвредно, проверить при обновлении `cryptography` до 49+.
- «Спроси про сеть» на **MySQL/MariaDB**-развёртывании честно
  отказывает — read-only SQLite-соединение специфично для SQLite,
  на MySQL для той же гарантии нужна отдельная read-only учётка на
  уровне СУБД, GridForge её сам не заводит.

## 7. Переменные окружения (сводка)

```
GRIDFORGE_DATABASE_URL          MySQL/MariaDB вместо SQLite по умолчанию
GRIDFORGE_DB_PATH               путь к SQLite-файлу (переопределяется тестами)
GRIDFORGE_SYSLOG_PORT           5140 по умолчанию
GRIDFORGE_NETFLOW_PORT          2055 по умолчанию
GRIDFORGE_RETENTION_SAMPLES_DAYS    30
GRIDFORGE_RETENTION_SYSLOG_DAYS     30
GRIDFORGE_RETENTION_CAPTURES_DAYS   7
GRIDFORGE_RETENTION_FLOWS_DAYS      3
GRIDFORGE_RETENTION_BACKUPS_KEEP    20 (на узел)
GRIDFORGE_LIFECYCLE_OFFLINE_DAYS    14
GRIDFORGE_AD_SERVER/_PORT/_DOMAIN/_DEFAULT_ROLE/_VERIFY_CERT   вход через AD
GRIDFORGE_OIDC_ISSUER/_CLIENT_ID/_CLIENT_SECRET/_DEFAULT_ROLE/
  _VERIFY_CERT/_REDIRECT_URI     вход через OIDC SSO
GRIDFORGE_ASK_MODEL             модель Gemini по умолчанию (переопределяется
                                 полем "URL" интеграции gemini)
```

Ключи внешних сервисов (MaxMind, Gemini, Graylog, Zabbix) — НЕ переменные
окружения, а зашифрованные записи `Integration` в БД, настраиваются на
странице «Интеграции» в интерфейсе.

## 8. Правила разработки (лицензионная чистота)

1. Писать от описания функции, не глядя в исходник Zabbix.
2. Идеи и архитектура — свободны; конкретный код, SQL-схема, формат
   протокола/конфигов Zabbix — нет.
3. Своя схема БД — ни одна таблица/поле не копируются 1:1.
4. Не скачивать готовые шаблоны Zabbix — только свои наборы поверх
   `Probe`/`Watch`; OID брать из MIB/документации вендора.
5. Не считать модуль «переписанным» из-за переименований.
6. Своя терминология (`Node`/`Probe`/`Sample`/`Watch`/`Incident`/
   `Signal`) — не возвращаться к `host`/`item`/`trigger`. Проверяется
   автоматически (`tests/test_naming_purity.py`) на каждом прогоне —
   поймала и исправила реальную утечку (`dc_host`/`live_hosts`,
   2026-09-25).

Перед релизом/продажей — чеклист «GridForge Rewrite Ledger» (артефакт
claude.ai) и юрист по IP, **до** подписания договора. Подробная справка
о происхождении кода и лицензиях сторонних зависимостей —
[docs/LICENSE-ORIGIN.md](docs/LICENSE-ORIGIN.md).

## 9. Карта кода

```
app/main.py             маршруты API, lifespan (планировщик+syslog+netflow)
app/models.py            все таблицы SQLAlchemy, докстринг — терминология
app/schemas.py            входные модели pydantic
app/db.py                движок БД, ручные миграции (add/rename column)
app/auth.py               API-ключи, роли, RBAC по группе
app/sessions.py, passwords.py, ad_auth.py, oidc_auth.py   вход

app/scheduler.py           опрос на мин-куче + фоновые расписания
app/probes.py, rate_engine.py                              исполнители проверок
app/watch_engine.py, escalation_engine.py                  Watch → Incident → эскалация
app/signal.py              webhook/telegram/apprise
app/actions_engine.py      действия по инциденту
app/templates_engine.py    шаблоны мониторинга

app/device_client.py, ssh_client.py, telnet_client.py      транспорт к оборудованию
app/credentials_engine.py, secrets_crypto.py                учётки и шифрование
app/backups_engine.py, audit_engine.py                      бэкапы и аудит конфигов
app/network_audit_engine.py, network_audit_facts.py,
app/network_audit_rules.py, risk_scoring.py                 аудит сети с риск-скором
app/ad_audit_engine.py, ad_audit_collector.py,
app/ad_audit_rules.py, ldap_engine.py                       AD-аудит
app/compliance_engine.py, config_search.py                  compliance/поиск по конфигу
app/vuln_scan_engine.py, vuln_register.py                   уязвимости
app/scan_engine.py, hub_detection_engine.py,
app/domain_scan_engine.py, mac_search_engine.py              разведка сети
app/cable_discovery_engine.py                                 журнал кабелей + CDP-автоопрос
app/scenarios_engine.py, scenario_catalog.py, sweep_engine.py,
app/sweep_commands.py                                          массовые операции
app/port_commands.py, port_security.py, stp_protection.py,
app/ports_engine.py                                            порты/Port Security/STP
app/firmware_store.py                                          образы ПО
app/console_ws.py                                              SSH-консоль в браузере
app/syslog_server.py, ip_lookup.py                             Syslog + IP-поиск
app/capture_engine.py                                          захват/анализ трафика
app/netflow_server.py                                          приёмник NetFlow v9
app/geoip_engine.py                                            GeoIP/ASN
app/lifecycle_engine.py                                        подсказки жизненного цикла
app/ask_engine.py                                              «Спроси про сеть» (Gemini)
app/integrations_engine.py                                     внешние сервисы (Graylog/Zabbix/MaxMind/Gemini)
app/metrics_engine.py                                          /metrics для Prometheus
app/dashboard_engine.py                                        сводка дашборда
app/inventory_engine.py                                        удаление узла со всеми зависимостями
app/retention_engine.py                                        очистка старых данных

static/                  30 страниц + common.js + style.css + vendor/xterm
tests/                   регрессия (naming purity, auth, channels, signal…)
docs/landscape-report.md обзор 8 open-source проектов + рекомендации §4
```
