FROM python:3.11

WORKDIR /app

# Instala Avahi y sus dependencias
#RUN apt-get update && apt-get install -y \
#    avahi-daemon \
#    avahi-utils \
#    && rm -rf /var/lib/apt/lists/*



# Copia el archivo de configuración de Avahi
#COPY avahi-service.conf /etc/avahi/services/socbarcelona.service

# Copia los requisitos e instala las dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=100 -r requirements.txt


# Crear carpeta del frontend (por si no existe)
#RUN mkdir -p /app/frontend

# Copia el resto de la aplicación
COPY . .





# 7. Copiar el contenido compilado a la carpeta del backend para servir con FastAPI
#RUN rm -rf /app/frontend && mkdir /app/frontend && cp -r build/* /app/frontend/

# Hace el script de entrada ejecutable
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]