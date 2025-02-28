FROM python:3.9

# Instalar cron y dependencias
RUN apt-get update && apt-get install -y cron && rm -rf /var/lib/apt/lists/*

# Establecer directorio de trabajo
WORKDIR /app

# Copiar archivos necesarios
COPY crontab /etc/cron.d/generate_rules_cron
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Aplicar permisos correctos al crontab
RUN chmod 0644 /etc/cron.d/generate_rules_cron && crontab /etc/cron.d/generate_rules_cron

# Iniciar el entrypoint
ENTRYPOINT ["/entrypoint.sh"]
