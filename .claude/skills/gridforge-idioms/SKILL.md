---
name: gridforge-idioms
description: Use when writing or reviewing GridForge backend code that touches scheduled/periodic checks, background-job recovery after restart, editing all static/*.html pages at once, polling network devices (SSH/Telnet/SNMP), comparing interface names, parallel SSH sweeps across a group, RBAC on group-scoped endpoints, or notifications that aren't tied to a Probe/Watch/Incident. Reuse these established patterns instead of re-deriving them.
---

# Устоявшиеся архитектурные идиомы GridForge

Повторно используй эти паттерны, не изобретай заново — каждый уже прошёл
через реальный баг или явное архитектурное решение.

- **Периодические проверки по расписанию** (день недели + время): смотри
  `VulnScanSchedule`/`run_due_vuln_schedules` (`app/vuln_scan_engine.py`)
  и `CableDiscoverySchedule`/`run_due_cable_discovery_schedules`
  (`app/cable_discovery_engine.py`) — оба проверяются раз в 60с из
  `Scheduler.run_forever()` (`app/scheduler.py`) через отдельный
  `asyncio.create_task()`, не `await` в цикле (иначе встанет опрос
  Probe на всё время долгого прогона). Guard от повторного срабатывания
  в тот же день — строковое поле `last_triggered_on` ("YYYY-MM-DD"),
  выставляется ДО прогона, не после.
- **Восстановление фоновых задач после рестарта**:
  `_recover_interrupted_background_jobs()` в `main.py` (вызывается в
  `lifespan` при каждом старте) помечает всё ещё `status="running"` НА
  МОМЕНТ СТАРТА процесса как прерванное — все реальные фоновые задачи
  создаются уже после этой точки, так что "running" на старте не может
  быть результатом живой задачи. Любой новый `asyncio.create_task()` с
  промежуточным статусом в БД должен встраиваться в этот список.
- **Правка HTML на всех страницах без редактирования каждого файла**:
  когда нужно что-то добавить/убрать на всех 27 `static/*.html` разом
  (favicon был правкой per-file — там нужен `<link>` до загрузки
  common.js), а когда можно — JS-инъекция из `common.js` в `initTopbar()`
  (так сделаны `.brand-badge`, `#sidebar-pin`, `#user-avatar`, удаление
  теглайна) — один файл вместо 27. `login.html` **не подключает**
  `common.js` (отдельная форма входа до авторизации) — для правок,
  которые должны быть и там, нужен per-file подход.
- **Опрос сетевых устройств**: единая точка — `app/device_client.py`
  (`run_device_command`), транспорт (SSH/Telnet) выбирается по
  `Node.vendor`, не вызывающим кодом. Пароли/ключи — через
  `resolve_credential(db, node)` (`app/credentials_engine.py`), не
  спрашивать пользователя заново, если для узла/группы уже настроена
  центральная учётка.
- **Имена интерфейсов бывают в двух форматах** — полное
  ("GigabitEthernet1/0/48", так отдаёт `show cdp neighbors detail`) и
  сокращённое ("Gi1/0/48", так хранит `PortSnapshot` из `show interfaces
  status`). Сравнивать напрямую строками — гарантированный баг (реальный
  случай 2026-09-24: автоопрос кабелей находил 0 совпадений на живом
  парке из-за этого). Всегда через `normalize_iface()`
  (`app/ports_engine.py`).
- **Массовый опрос группы узлов параллельно**: `asyncio.Semaphore` на
  8 одновременных SSH-сессий (см. `sweep_engine.py`, `hub_detection_engine.py`,
  `cable_discovery_engine.py`) — не увеличивать без причины, часть парка
  (старые 2950/2960) плохо переносит параллельные подключения.
- **RBAC по группе узлов**: любой эндпоинт, читающий/пишущий данные
  конкретной группы, обязан звать `key_sees_group(key, group_id)` —
  ограниченный по группе API-ключ должен получать 403 на чужую группу,
  не 404 (тест-сторож это проверяет по всем маршрутам из OpenAPI-схемы,
  см. HANDOFF.md §5).
- **Уведомление в обход Incident**: `Incident` жёстко привязан к `Watch`
  на `Probe` на уже существующем `Node` (см. терминологию в CLAUDE.md) —
  событие, у которого нет узла (например "найдено новое устройство",
  ещё не заведённое как Node), заводить как Incident было бы смысловой
  натяжкой. Для таких случаев — свой лёгкий путь мимо `signal.dispatch()`,
  см. `signal.notify_new_devices()`: переиспользует только расшифровку
  `Channel.config` и рассылку по `ChannelKind`, без формирования Incident.
  Уходит на все включённые каналы БЕЗ `node_id`/`watch_id` (сужение по
  конкретному узлу для события без узла бессмысленно). Тот же принцип —
  `FlowAlertRule`/`notify_flow_alert` (`app/flow_alerts_engine.py`) для
  пороговых оповещений по трафику: рассылка на ОДИН указанный в правиле
  канал, не на все сразу.
