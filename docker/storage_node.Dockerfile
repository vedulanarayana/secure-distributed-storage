FROM python:3.14-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY storage_node ./storage_node

CMD ["uvicorn", "storage_node.app:app", "--host", "0.0.0.0", "--port", "8000", \
     "--ssl-keyfile", "/certs/dev-key.pem", "--ssl-certfile", "/certs/dev-cert.pem"]
