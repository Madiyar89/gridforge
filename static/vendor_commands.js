// Команды для бэкапа по вендору — узкое подмножество справочника
// commands.html: только однострочные read-only show/display-команды без
// параметров (интерфейс/VLAN и т.п.), которые можно снять ОДНИМ SSH-
// вызовом (см. app/backups_engine.py:run_backup — одна команда, не
// многошаговый конфиг-режим). Многошаговые команды (VLAN/ACL/AAA и
// т.п.) из commands.html сюда намеренно не попадают — как единая
// строка через run_backup они не отработают так, как показаны в
// справочнике (там развёрнуты как раздельные шаги конфигурации).
//
// Ключи — значения Node.vendor из GridForge (см. app/models.py:Vendor):
// cisco_ios/cisco_ios_telnet используют один и тот же набор команд IOS.
// H3C/Huawei/MikroTik остаются только в справочнике commands.html —
// GridForge пока не отслеживает эти вендоры как Node.vendor, автоподбор
// команд для них здесь невозможен.
const VENDOR_COMMANDS = {
  cisco_ios: [
    { label: "Текущий конфиг", command: "show running-config" },
    { label: "Версия / модель", command: "show version" },
    { label: "Статус интерфейсов", command: "show ip interface brief" },
    { label: "MAC-таблица", command: "show mac address-table" },
    { label: "ARP", command: "show ip arp" },
    { label: "STP — статус", command: "show spanning-tree" },
  ],
  cisco_ios_telnet: [
    { label: "Текущий конфиг", command: "show running-config" },
    { label: "Версия / модель", command: "show version" },
    { label: "Статус интерфейсов", command: "show ip interface brief" },
    { label: "MAC-таблица", command: "show mac address-table" },
    { label: "ARP", command: "show ip arp" },
    { label: "STP — статус", command: "show spanning-tree" },
  ],
  junos: [
    { label: "Текущий конфиг", command: "show configuration" },
    { label: "Версия / модель", command: "show version" },
    { label: "Статус интерфейсов", command: "show interfaces terse" },
    { label: "MAC-таблица", command: "show ethernet-switching table" },
    { label: "ARP", command: "show arp" },
    { label: "STP — статус", command: "show spanning-tree bridge" },
  ],
};

const VENDOR_LABELS = {
  cisco_ios: "Cisco IOS",
  cisco_ios_telnet: "Cisco IOS (Telnet)",
  junos: "Juniper Junos",
};

// Заполняет <select> вариантами команд для набора вендоров (обычно один
// узел — один вендор, группа — может быть несколько сразу). Каждый
// option хранит саму команду в value; группировка по вендору через
// <optgroup>, если вендоров больше одного.
function populateCommandPicker(selectEl, vendors) {
  const known = vendors.filter((v) => VENDOR_COMMANDS[v]);
  if (known.length === 0) {
    selectEl.innerHTML = `<option value="">нет готовых команд для этого вендора</option>`;
    selectEl.disabled = true;
    return;
  }
  selectEl.disabled = false;
  selectEl.innerHTML =
    `<option value="">из справочника…</option>` +
    known
      .map((v) => {
        const options = VENDOR_COMMANDS[v]
          .map((c) => `<option value="${escapeHtml(c.command)}">${escapeHtml(c.label)}</option>`)
          .join("");
        return known.length > 1 ? `<optgroup label="${escapeHtml(VENDOR_LABELS[v] || v)}">${options}</optgroup>` : options;
      })
      .join("");
}
