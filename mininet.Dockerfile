FROM martimy/mininet

COPY ENTRYPOINT.sh /

RUN apt-get update && apt-get install -y \
    hping3 \
    iperf3 \
    nmap \
    tcpdump \
    strace \
    net-tools \
    iputils-ping \
    traceroute \
    curl \
    wget \
    vim \
    nano \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    scapy \
    numpy \
    pandas

RUN chmod +x /ENTRYPOINT.sh

WORKDIR /root

ENTRYPOINT ["/ENTRYPOINT.sh"]
