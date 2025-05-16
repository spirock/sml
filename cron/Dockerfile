FROM python:3.11

# Instalar cron y dependencias
RUN apt-get update && apt-get install -y cron && rm -rf /var/lib/apt/lists/*

# Establecer directorio de trabajo
WORKDIR /app


# Copiar archivos de configuración (pero NO los scripts Python)
COPY crontab /etc/cron.d/generate_rules_cron
COPY requirements.txt /app/requirements.txt

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN apt update && apt install -y --no-install-recommends suricata

# Copiar archivos necesarios
COPY crontab /etc/cron.d/generate_rules_cron
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Aplicar permisos correctos al crontab
RUN chmod 0644 /etc/cron.d/generate_rules_cron && crontab /etc/cron.d/generate_rules_cron

# Iniciar el entrypoint
ENTRYPOINT ["/entrypoint.sh"]
