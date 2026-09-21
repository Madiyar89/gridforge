// Аудит конфигураций сети — безстейтовый отчёт по узлам Cisco/Junos с
// бэкапом (26 правил, риск-скор из network_audit_rules.py). Рендер общий
// с AD-аудитом, см. risk-report.js.

const netReportPanel = createRiskReportPanel(
  "net",
  async () => {
    try {
      return await api("/api/network-audit/report");
    } catch (e) {
      return null;
    }
  },
  "Устройство",
  "devices",
  "Нет узлов с бэкапом Cisco/Junos"
);

function onKeySaved() {
  netReportPanel.load();
}

netReportPanel.load();
