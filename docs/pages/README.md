# Документация по страницам сайта

Не ТЗ на новую функциональность (для этого — `docs/specs/`), а **описание
текущего состояния** каждой страницы: что она делает сейчас, на каких
API держится, что видно как реальный пробел по факту чтения кода.

Цель — дать основу для чтения и дополнения: открываете файл нужной
страницы, читаете "как есть", дописываете свои пункты в "Идеи на
будущее". Когда идея дозревает до реальной задачи — переносите в
`docs/specs/NNN-....md` по шаблону `docs/specs/TEMPLATE.md`.

## Готово (31 из 31)

- [index.md](index.md) — главный дашборд (`static/index.html`)
- [inventory.md](inventory.md) — инвентарь узлов (`static/inventory.html`)
- [syslog.md](syslog.md) — просмотр syslog (`static/syslog.html`)
- [backups.md](backups.md) — бэкапы конфигураций (`static/backups.html`)
- [audit.md](audit.md) — аудит конфигураций, per-узел (`static/audit.html`)
- [network-audit.md](network-audit.md) — флот-отчёт по сети (`static/network-audit.html`)
- [scan.md](scan.md) — скан сети (`static/scan.html`)
- [ad-audit.md](ad-audit.md) — аудит Active Directory (`static/ad-audit.html`)
- [ask.md](ask.md) — вопрос про сеть на естественном языке (`static/ask.html`)
- [cables.md](cables.md) — кабельные схемы (`static/cables.html`)
- [capture.md](capture.md) — захват трафика (`static/capture.html`)
- [channels.md](channels.md) — каналы уведомлений (`static/channels.html`)
- [commands.md](commands.md) — справочник команд, статика (`static/commands.html`)
- [config-search.md](config-search.md) — поиск по конфигурациям (`static/config-search.html`)
- [console.md](console.md) — SSH-консоль в браузере (`static/console.html`)
- [credential-check.md](credential-check.md) — проверка учётных данных (`static/credential-check.html`)
- [credentials.md](credentials.md) — хранилище учётных данных (`static/credentials.html`)
- [domain-scan.md](domain-scan.md) — скан AD-домена (`static/domain-scan.html`)
- [firmware.md](firmware.md) — прошивки (`static/firmware.html`)
- [flows.md](flows.md) — потоки трафика (`static/flows.html`)
- [hubs.md](hubs.md) — вероятные хабы (`static/hubs.html`)
- [integrations.md](integrations.md) — интеграции Graylog/Zabbix/MaxMind/Gemini (`static/integrations.html`)
- [ldap.md](ldap.md) — LDAP-подключения (`static/ldap.html`)
- [login.md](login.md) — вход (`static/login.html`)
- [mac-search.md](mac-search.md) — поиск по MAC (`static/mac-search.html`)
- [ports.md](ports.md) — порты узла (`static/ports.html`)
- [rubka.md](rubka.md) — массовый прогон read-only команды (`static/rubka.html`)
- [scenarios.md](scenarios.md) — многошаговые сценарии (`static/scenarios.html`)
- [sync.md](sync.md) — синхронизация площадок (`static/sync.html`)
- [templates.md](templates.md) — шаблоны конфигурации (`static/templates.html`)
- [users.md](users.md) — пользователи и API-ключи (`static/users.html`)

Важная находка, зафиксированная в [integrations.md](integrations.md):
хранение и проверка соединения для Graylog/Zabbix уже реализованы
(`Integration` + `INTEGRATION_REGISTRY`), но ни один существующий
отчёт или панель реально не читает данные из них — решение
"Graylog отложен" в `docs/specs/001-dashboard-graphs.md` пока
остаётся в силе, но часть инфраструктуры под него уже готова.
