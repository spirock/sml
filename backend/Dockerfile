FROM python:3.11

WORKDIR /app

COPY requirements.txt .
#RUN pip install --no-cache-dir -r requirements.txt este no funciona en la rasberry por qu eneceista mas tiempo para ejecutarse
RUN pip install --no-cache-dir --default-timeout=100 -r requirements.txt


COPY . .

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]