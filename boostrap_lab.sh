#!/usr/bin/env bash
set -euo pipefail

### ─────────────────────────────
### VARIABLES (AJUSTA SI ES NECESARIO)
### ─────────────────────────────
# Interfaces (verifícalas con: ip a)
IF_EXT="enp0s8"    # NAT (salida a Internet)
IF_LAN="enp0s9"    # vmnet10 (red interna clientes)
IF_ATT="enp0s10"   # vmnet9  (red atacante/Kali)
IF_HOST="enp0s11"  # Host-Only (SSH desde tu Mac)

# Direcciones
IP_LAN_CIDR="192.168.10.1/24"
IP_ATT_CIDR="192.168.9.1/24"
IP_HOST_CIDR="192.168.56.10/24"

# Archivo netplan (el tuyo es 50-cloud-init.yaml)
NETPLAN_FILE="/etc/netplan/50-cloud-init.yaml"

### ─────────────────────────────
### FUNCIONES AUXILIARES
### ─────────────────────────────
add_rule_once() {
  # $1: tabla (-t nat opcional)  $2..$: resto de la regla con -A
  # Convierte -A a -C para comprobar y solo añade si no existe
  local table_arg="" ; local args=("$@")
  if [[ "${args[0]}" == "-t" ]]; then
    table_arg="-t ${args[1]}"
    args=("${args[@]:2}")
  fi
  local check=(iptables $table_arg -C "${args[@]:1}")
  local add=(iptables $table_arg "${args[@]}")
  if ! "${check[@]}" &>/dev/null; then
    "${add[@]}"
  fi
}

msg() { echo -e "\n\033[1;32m[+] $*\033[0m"; }

### ─────────────────────────────
### PREPARACIÓN
### ─────────────────────────────
[[ $EUID -ne 0 ]] && { echo "Ejecuta con sudo: sudo $0"; exit 1; }

msg "Actualizando índices APT"
apt-get update -y

### ─────────────────────────────
### INSTALAR SSH, GIT, HERRAMIENTAS BÁSICAS
### ─────────────────────────────
msg "Instalando OpenSSH server, Git y utilidades"
apt-get install -y openssh-server git ca-certificates curl gnupg lsb-release iptables-persistent netfilter-persistent

systemctl enable --now ssh

### ─────────────────────────────
### INSTALAR DOCKER (repos oficiales, SIN snap)
### ─────────────────────────────
msg "Instalando Docker CE desde repos oficiales"
install -m 0755 -d /etc/apt/keyrings
if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
fi
UBU_CODENAME=$(lsb_release -cs)
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${UBU_CODENAME} stable" \
  | tee /etc/apt/sources.list.d/docker.list >/dev/null

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker

# Añadir usuario actual al grupo docker (para usar sin sudo)
THE_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "$USER")}"
if getent group docker >/dev/null; then
  usermod -aG docker "$THE_USER" || true
fi

### ─────────────────────────────
### CONFIGURAR NETPLAN (4 NICs)
### ─────────────────────────────
msg "Configurando Netplan en ${NETPLAN_FILE}"
backup="${NETPLAN_FILE}.bak.$(date +%F_%H%M%S)"
[[ -f "$NETPLAN_FILE" ]] && cp -a "$NETPLAN_FILE" "$backup"

cat > "$NETPLAN_FILE" <<EOF
network:
  version: 2
  ethernets:
    ${IF_EXT}:
      dhcp4: true
    ${IF_LAN}:
      dhcp4: no
      addresses:
        - ${IP_LAN_CIDR}
    ${IF_ATT}:
      dhcp4: no
      addresses:
        - ${IP_ATT_CIDR}
    ${IF_HOST}:
      dhcp4: no
      addresses:
        - ${IP_HOST_CIDR}
EOF

chmod 600 "$NETPLAN_FILE"
netplan apply

### ─────────────────────────────
### HABILITAR FORWARDING + NAT
### ─────────────────────────────
msg "Habilitando IPv4 forwarding"
# Persistente
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-forwarding.conf
sysctl --system >/dev/null

msg "Creando reglas de iptables (idempotentes) y guardando"
# NAT LAN -> Internet
add_rule_once -t nat -A POSTROUTING -o "${IF_EXT}" -j MASQUERADE
# Permitir salida LAN -> EXT y retorno
add_rule_once -A FORWARD -i "${IF_LAN}" -o "${IF_EXT}" -j ACCEPT
add_rule_once -A FORWARD -i "${IF_EXT}" -o "${IF_LAN}" -m state --state RELATED,ESTABLISHED -j ACCEPT

# (Opcional) NO habilitamos tránsito entre vmnet9 (Kali) y vmnet10 para mantener el aislamiento.
# Si algún día quieres permitirlo, añade reglas similares para ${IF_ATT} <-> ${IF_LAN}.

# Guardar reglas persistentes
netfilter-persistent save

### ─────────────────────────────
### RESUMEN
### ─────────────────────────────
msg "Hecho. Resumen rápido:"
ip -o -4 addr show | awk '{print "- " $2 ": " $4}'
echo
echo "Usuario añadido al grupo docker: ${THE_USER}  (si es tu usuario, cierra sesión o reinicia para que surta efecto)."
echo "SSH activo. Si configuraste Host-Only en ${IF_HOST}, conéctate desde tu Mac:"
echo "  ssh ${THE_USER}@$(echo ${IP_HOST_CIDR} | cut -d/ -f1)"