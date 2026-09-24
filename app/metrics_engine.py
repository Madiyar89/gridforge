"""Экспорт метрик в формате Prometheus (`/metrics`) — п.4.3 из
docs/landscape-report.md ("Endpoint /metrics для Prometheus", источник
идеи: NetAlertX и ntopng оба отдают такой эндпоинт из коробки).

Текст формата собирается вручную (без библиотеки `prometheus_client`) —
набор метрик небольшой (гейджи, без histogram/summary), а формат
экспозиции — обычный текст (`# HELP`/`# TYPE`/`name value`), тащить
отдельную зависимость ради этого незачем.

Данные переиспользуют dashboard_engine.build_dashboard — та же RBAC-
область видимости (Principal.group_id), что и у самого дашборда: ключ,
ограниченный одной группой, увидит метрики только по своим узлам, не по
всему парку. Отдельный provided-суффикс "_total" — соглашение Prometheus
для счётчиков-состояний, здесь формально гейджи (значение может
уменьшаться), но суффикс сохранён для единообразия с другими экспортёрами
сетевого мониторинга (то же соглашение у node_exporter/ntopng)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.auth import Principal, scope_nodes
from app.dashboard_engine import build_dashboard
from app.models import Node, Probe


def _gauge(lines: list[str], name: str, help_text: str, value: float) -> None:
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} gauge")
    lines.append(f"{name} {value}")


def render_prometheus_metrics(db: Session, key: Principal) -> str:
    dash = build_dashboard(db, key)
    node_ids = [row[0] for row in scope_nodes(db.query(Node.id), key).all()]
    probes_enabled = (
        db.query(Probe).filter(Probe.node_id.in_(node_ids), Probe.enabled.is_(True)).count()
        if node_ids
        else 0
    )

    lines: list[str] = []
    _gauge(lines, "gridforge_nodes_total", "Узлов в области видимости ключа", dash["nodes"]["total"])
    _gauge(lines, "gridforge_nodes_active", "Активных (не отключённых) узлов", dash["nodes"]["active"])
    _gauge(lines, "gridforge_nodes_silent", "Узлов без единого измерения за 24ч", dash["nodes"]["silent"])
    _gauge(lines, "gridforge_probes_enabled", "Включённых проверок (Probe)", probes_enabled)
    _gauge(lines, "gridforge_incidents_open", "Открытых инцидентов, всего", dash["incidents"]["total"])
    _gauge(lines, "gridforge_incidents_open_critical", "Открытых инцидентов, critical", dash["incidents"]["critical"])
    _gauge(lines, "gridforge_incidents_open_warning", "Открытых инцидентов, warning", dash["incidents"]["warning"])
    _gauge(lines, "gridforge_backups_last_24h", "Снятых бэкапов за 24ч", dash["backups"]["last_24h"])
    _gauge(lines, "gridforge_backups_failed_24h", "Бэкапов с ошибкой за 24ч", dash["backups"]["failed_24h"])
    _gauge(lines, "gridforge_backups_never_taken", "Узлов, для которых не было ни одного бэкапа", dash["backups"]["never_backed_up"])
    _gauge(lines, "gridforge_audit_findings_failed", "Проваленных правил аудита конфигурации", dash["audit"]["failed"])
    _gauge(lines, "gridforge_syslog_messages_24h", "Сообщений syslog за 24ч", dash["syslog"]["last_24h"])
    _gauge(lines, "gridforge_syslog_errors_24h", "Сообщений syslog severity<=3 (emergency..error) за 24ч", dash["syslog"]["errors_24h"])
    return "\n".join(lines) + "\n"
