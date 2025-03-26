FROM nginx:alpine

# Copia archivos build de React al directorio de Nginx
COPY frontend/build /usr/share/nginx/html

# Copia configuración personalizada de Nginx
COPY nginx.conf /etc/nginx/conf.d/default.conf




