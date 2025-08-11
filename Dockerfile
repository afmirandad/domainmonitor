FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl \
    dnsutils \
    gcc \
    git \
    jq \
    build-essential \
    libssl-dev \
    libffi-dev \
    wget \
    unzip \
    nmap \
    && apt-get clean

ENV GO_VERSION=1.21.3
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

WORKDIR /app

COPY entrypoint.py email_notifier.py requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "entrypoint.py"]
