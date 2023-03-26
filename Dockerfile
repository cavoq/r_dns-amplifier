FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y dnsutils bash curl jq make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /dns-bash

COPY dns-bash.sh .
COPY Makefile .
COPY .env .

CMD ["/bin/bash"]