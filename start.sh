#!/bin/sh

if [ -z "$VPNADDR" ] || [ -z "$VPNUSER" ] || [ -z "$VPNPASS" ]; then
  echo "Variables VPNADDR, VPNUSER and VPNPASS must be set."
  exit 1
fi

export VPNTIMEOUT=${VPNTIMEOUT:-30}

# Setup masquerade for container as gateway
for iface in $(ip a | grep eth | grep inet | awk '{print $2}'); do
  iptables -t nat -A POSTROUTING -s "$iface" -j MASQUERADE 2>/dev/null || true
done

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# Set DNS
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf

while true; do
  echo "------------ VPN Starts ------------"
  /usr/bin/forticlient
  echo "------------ VPN exited ------------"
  sleep 10
done