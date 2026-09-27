# GridForge (собственный Python-проект, НЕ форк Zabbix — см. README.md)
FROM python:3.12-slim
# Корпоративный root CA (TLS-инспекция на этой сети) — без него ни apt,
# ни pip не достучатся до внешних зеркал. Тот же файл, что уже используют
# другие сервисы в этой инфраструктуре (NetOpsHub backend/ansible-runner).
COPY corporate-ca.crt /usr/local/share/ca-certificates/corporate-ca.crt
RUN update-ca-certificates
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap tshark iputils-ping ca-certificates curl unzip git libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
# Непривилегированный пользователь для рантайма (security-аудит: контейнер
# работал от root, хотя HANDOFF.md §2 декларирует "не от root" для этого
# сервиса). Создаём здесь, ДО git clone шаблонов Nuclei ниже — они кладутся
# сразу в $HOME этого пользователя, потому что run_nuclei_scan() (см.
# app/vuln_scan_engine.py) не передаёт nuclei флаг -t: бинарник сам ищет
# шаблоны в "$HOME/nuclei-templates" (та же причина, по которой раньше это
# работало под root с /root/nuclei-templates — $HOME совпадал).
RUN useradd --system --create-home --home-dir /home/gridforge --shell /usr/sbin/nologin gridforge
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --retries 10 --timeout 120 --cert /usr/local/share/ca-certificates/corporate-ca.crt -r requirements.txt
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
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /home/gridforge/nuclei-templates \
    && rm -rf /home/gridforge/nuclei-templates/.git \
    && chown -R gridforge:gridforge /home/gridforge/nuclei-templates
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
COPY --chown=gridforge:gridforge app/ ./app/
COPY --chown=gridforge:gridforge static/ ./static/
RUN mkdir -p /app/data && chown -R gridforge:gridforge /app
# Точечные capability на конкретные бинарники вместо root-контейнера целиком:
# docker-compose.yml даёт контейнеру NET_RAW+NET_ADMIN (нужны nmap для
# scan_engine.py и dumpcap для capture_engine.py), но без setcap эти
# capability эффективны только для root-процесса — non-root процесс их не
# получает автоматически. libcap2-bin (apt, выше) даёт команду setcap.
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
EXPOSE 8100 5140/udp
USER gridforge
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
