# GridForge (собственный Python-проект, НЕ форк Zabbix — см. README.md)
FROM python:3.12-slim
# Корпоративный root CA (TLS-инспекция на этой сети) — без него ни apt,
# ни pip не достучатся до внешних зеркал. Тот же файл, что уже используют
# другие сервисы в этой инфраструктуре (NetOpsHub backend/ansible-runner).
COPY corporate-ca.crt /usr/local/share/ca-certificates/corporate-ca.crt
RUN update-ca-certificates
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap tshark iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --retries 10 --timeout 120 --cert /usr/local/share/ca-certificates/corporate-ca.crt -r requirements.txt
# impacket вендорён (см. requirements.txt — комментарий про BrokenPipeError
# на прокси), файлы взяты из уже рабочей установки, кладём напрямую в
# site-packages вместо pip install.
COPY vendor/impacket /usr/local/lib/python3.12/site-packages/impacket
COPY vendor/impacket-0.12.0.dist-info /usr/local/lib/python3.12/site-packages/impacket-0.12.0.dist-info
COPY app/ ./app/
COPY static/ ./static/
RUN mkdir -p /app/data
EXPOSE 8100 5140/udp
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
