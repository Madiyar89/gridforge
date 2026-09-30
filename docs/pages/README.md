# Документация по страницам сайта

Не ТЗ на новую функциональность (для этого — `docs/specs/`), а **описание
текущего состояния** каждой страницы: что она делает сейчас, на каких
API держится, что видно как реальный пробел по факту чтения кода.

Цель — дать основу для чтения и дополнения: открываете файл нужной
страницы, читаете "как есть", дописываете свои пункты в "Идеи на
будущее". Когда идея дозревает до реальной задачи — переносите в
`docs/specs/NNN-....md` по шаблону `docs/specs/TEMPLATE.md`.

## Готово

- [index.md](index.md) — главный дашборд (`static/index.html`)
- [inventory.md](inventory.md) — инвентарь узлов (`static/inventory.html`)
- [syslog.md](syslog.md) — просмотр syslog (`static/syslog.html`)
- [backups.md](backups.md) — бэкапы конфигураций (`static/backups.html`)
- [audit.md](audit.md) — аудит конфигураций, per-узел (`static/audit.html`)
- [network-audit.md](network-audit.md) — флот-отчёт по сети (`static/network-audit.html`)
- [scan.md](scan.md) — скан сети (`static/scan.html`)

## Ещё не разобрано (24 страницы)

`ad-audit`, `ask`, `cables`, `capture`, `channels`, `commands`,
`config-search`, `console`, `credential-check`, `credentials`,
`domain-scan`, `firmware`, `flows`, `hubs`, `integrations`, `ldap`,
`login`, `mac-search`, `ports`, `rubka`, `scenarios`, `sync`,
`templates`, `users` — добавлять по мере необходимости, тем же
форматом.
