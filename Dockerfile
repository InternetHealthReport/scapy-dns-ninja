FROM python:3.11-slim

# tcpdump provides libpcap which scapy uses for sniffing/BPF filters
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump libpcap-dev iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/app/docker-entrypoint.sh"]

