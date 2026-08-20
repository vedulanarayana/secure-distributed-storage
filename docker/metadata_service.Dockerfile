FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY metadata_service ./metadata_service
COPY anomaly ./anomaly
COPY client ./client

RUN python -m anomaly.train

CMD ["uvicorn", "metadata_service.app:app", "--host", "0.0.0.0", "--port", "8000", \
     "--ssl-keyfile", "/certs/dev-key.pem", "--ssl-certfile", "/certs/dev-cert.pem"]
