FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN useradd --system --uid 10001 --no-create-home proxyapi

# Certificado TLS autoassinado, gerado no build
ARG TLS_SAN="DNS:localhost,IP:127.0.0.1"
RUN mkdir /certs \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -keyout /certs/proxy.key -out /certs/proxy.crt \
      -subj "/CN=sysreptor-ro-proxy" -addext "subjectAltName=${TLS_SAN}" \
 && chown -R 10001 /certs && chmod 600 /certs/proxy.key

USER 10001
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", \
     "--ssl-certfile", "/certs/proxy.crt", "--ssl-keyfile", "/certs/proxy.key"]
