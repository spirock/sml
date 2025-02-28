# Usamos la imagen oficial de Suricata
FROM jasonish/suricata:latest

# Instalar suricata-update y dependencias
RUN apt update && \
    apt install -y suricata-update  && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Descargar las reglas al construir el contenedor
RUN suricata-update && suricata-update update-sources

# Dar permisos de ejecución al script de entrada
RUN chmod +x /app/entrypoint.sh

# Definir el entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Definimos el volumen para los logs y la configuración
VOLUME ["/etc/suricata", "/var/log/suricata"]

# Definimos el comando por defecto para ejecutar Suricata
CMD ["-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]
