FROM python:3.7-alpine

LABEL maintainer="info@opsmx.io"
LABEL version="1.0"
LABEL description="A small container that mimics HashiCorp Enterprise Vault \
policy integration with HashiCorp Sentinel"

COPY ./app /app
WORKDIR /app

RUN pip install -r requirements.txt
EXPOSE 8200

CMD ["python", "vault-lite.py"]
