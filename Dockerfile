##
# Build stage
##
FROM python:3.7-slim-buster AS builder

LABEL maintainer="info@opsmx.io"
LABEL version="1.0"
LABEL description="A small container that mimics HashiCorp Enterprise Vault \
policy integration with HashiCorp Sentinel"

# example of a development library package that needs to be installed
RUN apt-get -qy update && \
  apt-get -qy upgrade && \
  apt-get -y install wget unzip && \
  rm -rf /var/cache/apt/* /var/lib/apt/lists/*

RUN pip3 install virtualenv
RUN python3 -m virtualenv /venv

ENV SENTINEL_VER=0.15.4
RUN wget https://releases.hashicorp.com/sentinel/$SENTINEL_VER/sentinel_${SENTINEL_VER}_linux_amd64.zip && \
  unzip sentinel_${SENTINEL_VER}_linux_amd64.zip && \
  mv sentinel /venv/bin

COPY ./app /app
WORKDIR /app

RUN . /venv/bin/activate && pip3 install -r requirements.txt

##
# the second, production stage can be much more lightweight:
##
FROM python:3.7-slim-buster

ENV GROUP_ID=1000 \
    USER_ID=1000

COPY --from=builder /venv /venv

ADD app /app
WORKDIR /app

RUN addgroup --gid $GROUP_ID www
RUN adduser --shell /usr/sbin/nologin --system --uid $USER_ID --gid $GROUP_ID www

RUN mkdir /app/vault-lite-store && chown -R www /app/vault-lite-store/
USER www
WORKDIR /app

expose 8200

CMD ["./startup.sh"]
