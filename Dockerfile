FROM ubuntu:22.04

ENV VPNADDR \
    VPNUSER \
    VPNPASS

ENV DEBIAN_FRONTEND=noninteractive

# Устанавливаем пакеты
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    expect \
    iproute2 \
    iptables \
    wget \
    unzip \
    nmap \
    jq \
    git \
    python3 \
    python3-pip \
    ppp \
    iputils-ping \
    netcat-openbsd \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

# FortiClient SSLVPN
RUN wget 'https://hadler.me/files/forticlient-sslvpn_4.4.2329-1_amd64.deb' -O forticlient-sslvpn_amd64.deb && \
    dpkg -x forticlient-sslvpn_amd64.deb /usr/share/forticlient && \
    rm forticlient-sslvpn_amd64.deb

RUN mkdir -p /etc/ppp && \
    /usr/share/forticlient/opt/forticlient-sslvpn/64bit/helper/setup.linux.sh 2

# NetExec
RUN git clone --depth=1 https://github.com/Pennyw0rth/NetExec.git /tmp/nxc && \
    cd /tmp/nxc && \
    pip3 install . && \
    rm -rf /tmp/nxc

# Скрипты
COPY forticlient /usr/bin/forticlient
COPY start.sh /start.sh
RUN chmod +x /start.sh /usr/bin/forticlient

CMD ["/start.sh"]