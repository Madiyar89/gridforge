# GridForge (собственный Python-проект, НЕ форк Zabbix — см. README.md)
FROM python:3.12-slim
# Опциональный corporate/state root CA — см. certs/README.md. Папка
# пустая по умолчанию (публичная сборка проходит без изменений); если
# твоя сеть перехватывает TLS, положи туда свой .crt локально (в
# .gitignore, в репозиторий не попадёт).
COPY certs/ /usr/local/share/ca-certificates/
RUN update-ca-certificates
# PIP_CERT — иначе pip использует свой встроенный набор корневых (certifi),
# не системный — добавленный выше корпоративный CA не подхватится сам
# по себе без этой переменной.
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap tshark iputils-ping ca-certificates curl unzip git libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Non-root runtime user, fixed UID/GID for predictable volume ownership
# across redeploys (gridforge_data is a named volume — see docker-compose.yml).
RUN groupadd -g 10001 gridforge && \
    useradd -u 10001 -g gridforge -M -d /app -s /usr/sbin/nologin gridforge
COPY requirements.txt .
RUN pip install --no-cache-dir --retries 10 --timeout 120 -r requirements.txt
# impacket вендорён (см. requirements.txt — комментарий про BrokenPipeError
# на прокси), файлы взяты из уже рабочей установки, кладём напрямую в
# site-packages вместо pip install.
COPY vendor/impacket /usr/local/lib/python3.12/site-packages/impacket
COPY vendor/impacket-0.12.0.dist-info /usr/local/lib/python3.12/site-packages/impacket-0.12.0.dist-info
# nuclei (ProjectDiscovery, MIT, см. app/vuln_scan_engine.py:run_nuclei_scan)
# — бинарник с GitHub releases, не apt: пакет доступен только на Kali
# (kali-rolling), этот образ — обычный Debian slim, где его в принципе
# нет. Версия зафиксирована явно, тот же принцип, что у impacket выше —
# не latest, чтобы сборка не менялась незаметно.
#
# Шаблоны — РЕАЛЬНАЯ находка 2026-09-25 (прошлая сессия оставила это
# заблокированным, см. историю CLAUDE.md): `nuclei -update-templates` и
# прямая закачка .zip с codeload.github.com/GitHub release assets
# стабильно обрывались на ~4.8МБ (`stream error`/`connection reset by
# peer`) — проверено на ДВУХ разных машинах в этой инфраструктуре
# (не совпадение и не разовая перегрузка сети, как предполагала прошлая
# сессия, а системное ограничение корпоративного прокси на размер
# ОДНОГО HTTP-ответа; codeload к тому же не поддерживает Range —
# докачать оборванное тоже нельзя). `git clone` того же контента прошёл
# без единой ошибки на всех ~14000 файлах (~100МБ) — smart-HTTP
# передаёт данные иначе (чанками через персистентное соединение), и
# прокси это не режет. Поэтому шаблоны здесь клонируются git, а не
# через встроенный апдейтер nuclei — тот же результат, разный транспорт.
# Cloned under /app (== gridforge user's $HOME, see useradd -d above),
# not /root: nuclei's default template auto-detection resolves relative
# to $HOME, and root's home dir would not be readable by the non-root
# runtime user below. Verified empirically against this exact image/
# nuclei version (see deploy notes) — not just assumed from docs.
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /app/nuclei-templates \
    && rm -rf /app/nuclei-templates/.git
ARG NUCLEI_VERSION=3.11.1
RUN curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip
# feroxbuster (epi052, MIT, docs/landscape-report.md — второй инструмент
# после Nuclei, см. app/vuln_scan_engine.py:run_web_discovery_scan) — тот
# же путь, что у nuclei выше: релизный .zip с GitHub, не apt (kali-only
# пакет), версия зафиксирована явно. Release-ассет (не codeload-архив,
# как у шаблонов Nuclei) — тот же класс закачки, что уже надёжно
# работает для самого бинарника nuclei (~6-7МБ), прокси не режет.
ARG FEROXBUSTER_VERSION=2.13.1
RUN curl -fsSL -o /tmp/ferox.zip \
        "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/x86_64-linux-feroxbuster.zip" \
    && unzip -o /tmp/ferox.zip -d /usr/local/bin feroxbuster \
    && chmod +x /usr/local/bin/feroxbuster \
    && rm /tmp/ferox.zip
COPY app/ ./app/
COPY static/ ./static/
RUN mkdir -p /app/data
# File-based capabilities: docker-compose.yml grants NET_RAW/NET_ADMIN into
# the container's capability bounding set (cap_add), but a non-root process
# only gets to exercise them if the specific binary carries them itself.
# setcap here does that for nmap (scan_engine.py's -sT connect scan and
# domain_scan_engine.py's -sn ping sweep, and vuln_scan_engine.py's
# ping/quick/vuln/full_ports profiles all use unprivileged scan types and
# were verified end-to-end as this non-root user + cap_add) and dumpcap
# (capture_engine.py — the actual packet-capturing component; live capture
# on an interface was verified end-to-end too).
#
# KNOWN LIMITATION (verified empirically, not just capability plumbing):
# nmap's -sS (SYN scan) and -O (OS detection — vuln_scan_engine.py's
# 'os' profile) hard-check geteuid() == 0 in nmap's own source and refuse
# to run for a non-root process EVEN WITH cap_net_raw/cap_net_admin
# correctly set via setcap and present in the capability bounding set:
#   "TCP/IP fingerprinting (for OS scan) requires root privileges."
#   "You requested a scan type which requires root privileges."
# This is not fixable by setcap/capabilities alone — nmap does not use a
# capability-aware check for these two scan types. The 'os' profile in
# vuln_scan_engine.py's PROFILE_ARGS will fail for the non-root gridforge
# user until this is addressed deliberately (e.g. a narrowly-scoped
# setuid wrapper just for that profile, or accepting/disabling it).
#
# tshark is deliberately NOT setcap'd: in this codebase it is only ever run
# with -r against a file dumpcap already wrote, never for live capture, so
# it needs no raw-socket capability (least privilege).
#
# /usr/bin/ping (app/probes.py icmp_ping) also needs this explicitly: this
# Debian slim base ships it WITHOUT setuid-root or file capabilities set
# (verified empirically -- getcap/ls -la on the built image showed neither),
# unlike some distros where iputils-ping is pre-hardened via the package's
# own postinst. Under the old root-uid container this was masked because
# root never needs CAP_NET_RAW to open a raw socket; as the non-root
# gridforge user it would otherwise fail with
# "ping: socket: Operation not permitted".
RUN setcap 'cap_net_raw,cap_net_admin+eip' /usr/bin/nmap && \
    setcap 'cap_net_raw,cap_net_admin+eip' /usr/bin/dumpcap && \
    setcap 'cap_net_raw+eip' /usr/bin/ping
RUN chown -R gridforge:gridforge /app
USER gridforge
EXPOSE 8100 5140/udp
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
