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
    pkg-config \
    && apt-get clean



WORKDIR /app

COPY requirements.txt ./
COPY app/ ./app/

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "-m", "app.domainenumeration"]
