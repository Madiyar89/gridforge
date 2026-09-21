# Docker-развёртывание (2026-09-21)

Помимо systemd-варианта (`deploy/gridforge.service`, для локальной машины) —
Docker-путь для развёртывания на общих/боевых серверах, где нельзя ставить
пакеты в систему напрямую (см. инцидент в дневнике `gridforge-zabbix-fork`
про случайно остановленную MariaDB на `.244` — с тех пор только так).

```bash
docker compose build
docker compose up -d
docker logs gridforge   # тут при первом запуске покажет Admin-пароль и API-ключ — сохранить сразу
```

- Порт **8100** — веб/API, **5140/UDP** — syslog.
- БД — SQLite в volume `gridforge_data` (не MariaDB, это дефолт самого
  проекта, см. `app/db.py` — `GRIDFORGE_DATABASE_URL` можно переопределить
  на MySQL, если понадобится).
- `nmap`/`tshark` (для `scan_engine.py`/`capture_engine.py`) — внутри
  образа, с `cap_add: NET_RAW, NET_ADMIN` в compose (не полный root).
- `corporate-ca.crt` — корпоративный root CA (TLS-инспекция на этой сети),
  без него ни `apt`, ни `pip` не достучатся наружу при сборке образа. Тот
  же файл, что уже в NetOpsHub-backend.
- Развёрнуто и проверено на **192.0.2.244** (порт 8100, доп. к уже
  работающему там NetOps Hub/GridForge-Zabbix-fork/phonebook — конфликтов
  портов нет).
