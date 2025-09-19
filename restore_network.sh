#!/usr/bin/env bash
set -e

# Interfaces
IF_EXT="enp0s8"   # salida a Internet (NAT)
IF_LAN="enp0s9"   # red interna clientes (192.168.10.0/24)

echo "[+] Restaurando configuración de red..."

# 1. Habilitar IPv4 forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# 2. Reglas NAT y FORWARD
iptables -A FORWARD -i ${IF_LAN} -o ${IF_EXT} -j ACCEPT
iptables -A FORWARD -i ${IF_EXT} -o ${IF_LAN} -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -o ${IF_EXT} -j MASQUERADE

# 3. Guardar reglas para reinicios futuros
netfilter-persistent save

echo "[+] Reglas restauradas. Verifica con: ping -c 3 8.8.8.8 desde el cliente."