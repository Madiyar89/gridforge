# GridForge (собственный Python-проект, НЕ форк Zabbix — см. README.md)
FROM python:3.12-slim
# Корпоративный root CA (TLS-инспекция на этой сети) — без него ни apt,
# ни pip не достучатся до внешних зеркал. Тот же файл, что уже используют
# другие сервисы в этой инфраструктуре (NetOpsHub backend/ansible-runner).
COPY corporate-ca.crt /usr/local/share/ca-certificates/corporate-ca.crt
RUN update-ca-certificates
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap tshark iputils-ping ca-certificates curl unzip git \
    && rm -rf /var/lib/apt/lists/*
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
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates \
    && rm -rf /root/nuclei-templates/.git
ARG NUCLEI_VERSION=3.11.1
RUN curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip
COPY app/ ./app/
COPY static/ ./static/
RUN mkdir -p /app/data
EXPOSE 8100 5140/udp
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
