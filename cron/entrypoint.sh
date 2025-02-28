#!/bin/bash

# Archivo de logs para la tarea cron
LOG_FILE="/var/log/generate_rules_cron.log"

# Crear el archivo de log si no existe
touch $LOG_FILE
chmod 666 $LOG_FILE  # Permitir escritura para cron

# Aplicar permisos correctos al crontab
chmod 0644 /etc/cron.d/generate_rules_cron
crontab /etc/cron.d/generate_rules_cron

# Iniciar el servicio cron en segundo plano
echo "🚀 Iniciando cron..."
service cron start

# Esperar hasta que el archivo de log tenga contenido antes de leerlo
echo "⏳ Esperando logs de ejecución..."
while [ ! -s "$LOG_FILE" ]; do
    sleep 5
done

# Mostrar logs en tiempo real
tail -f $LOG_FILE
