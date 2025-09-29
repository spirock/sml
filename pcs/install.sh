#!/usr/bin/env bash
# Instalación de herramientas de ofensiva SOLO para LAB.
# Funciona en Debian/Ubuntu mínimos. Reintenta vía Git si APT falla.

set -u
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo "; else echo "Se requiere root o sudo"; exit 1; fi
fi

say() { printf "\033[1;34m[+] %s\033[0m\n" "$*"; }
warn(){ printf "\033[1;33m[!] %s\033[0m\n" "$*"; }
err() { printf "\033[1;31m[x] %s\033[0m\n" "$*"; }

APT_INSTALL(){
  $SUDO bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y $*" || return 1
}

# --- prerequisitos base ---
say "Actualizando índices APT"
$SUDO apt-get update -y || true

say "Instalando toolchain y dependencias de build"
APT_INSTALL git curl wget python3 python3-pip python3-venv perl make gcc g++ pkg-config cmake \
            libssl-dev libssh-dev zlib1g-dev libpq-dev libsvn-dev libidn11-dev libpcre3-dev \
            libgcrypt20-dev libgpg-error-dev libcurl4-openssl-dev libpcap-dev || true

# Añadir ~/.local/bin al PATH si se usa pip --user
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
  warn "Añadiendo ~/.local/bin al PATH para esta sesión"
  export PATH="$HOME/.local/bin:$PATH"
fi

# Directorio de fuentes
TOOLS_DIR="/opt/tools"
$SUDO mkdir -p "$TOOLS_DIR"
$SUDO chown -R "$(id -u)":"$(id -g)" "$TOOLS_DIR" 2>/dev/null || true

# Wrapper helper
link_bin(){  # link_bin <origen> <destino-sin-ext>
  local src="$1" dst="/usr/local/bin/$2"
  $SUDO install -m 0755 "$src" "$dst" 2>/dev/null || $SUDO ln -sf "$src" "$dst"
  say "Creado wrapper $dst -> $src"
}

# --- Instalación con fallback por herramienta ---

# 1) nmap (APT)
if command -v nmap >/dev/null; then say "nmap ya instalado"; else
  say "Instalando nmap por APT"; APT_INSTALL nmap || err "nmap: fallo APT"
fi

# 2) hping3 (APT; compilar si falla)
if command -v hping3 >/dev/null; then say "hping3 ya instalado"; else
  say "Instalando hping3 por APT"; if ! APT_INSTALL hping3; then
    warn "APT falló. Compilando hping3 desde fuente"
    cd "$TOOLS_DIR" && rm -rf hping || true
    git clone --depth=1 https://github.com/antirez/hping.git && cd hping || err "clone hping"
    ./configure || true
    make -j"$(nproc)" && $SUDO make install || err "hping3 build/install falló"
  fi
fi

# 3) slowhttptest (APT; compilar si falla)
if command -v slowhttptest >/dev/null; then say "slowhttptest ya instalado"; else
  say "Instalando slowhttptest por APT"; if ! APT_INSTALL slowhttptest; then
    warn "APT falló. Compilando slowhttptest desde fuente"
    cd "$TOOLS_DIR" && rm -rf slowhttptest || true
    git clone --depth=1 https://github.com/shekyan/slowhttptest.git && cd slowhttptest || err "clone slowhttptest"
    cmake . || ./configure || true
    make -j"$(nproc)" && $SUDO make install || err "slowhttptest build/install falló"
  fi
fi

# 4) nikto (APT o Git)
if command -v nikto >/dev/null; then say "nikto ya instalado"; else
  say "Instalando nikto por APT"; if ! APT_INSTALL nikto; then
    warn "APT falló. Instalando nikto desde Git"
    cd "$TOOLS_DIR" && rm -rf nikto || true
    git clone --depth=1 https://github.com/sullo/nikto.git && cd nikto || err "clone nikto"
    link_bin "$PWD/program/nikto.pl" nikto
  fi
fi

# 5) sqlmap (Git preferido)
if command -v sqlmap >/dev/null; then say "sqlmap ya instalado"; else
  say "Instalando sqlmap desde Git"
  cd "$TOOLS_DIR" && rm -rf sqlmap || true
  git clone --depth=1 https://github.com/sqlmapproject/sqlmap.git && cd sqlmap || err "clone sqlmap"
  $SUDO ln -sf "$PWD/sqlmap.py" /usr/local/bin/sqlmap && $SUDO chmod +x /usr/local/bin/sqlmap
fi

# 6) xsstrike (Git + pip reqs)
if command -v xsstrike >/dev/null; then say "xsstrike ya instalado"; else
  say "Instalando XSStrike desde Git"
  cd "$TOOLS_DIR" && rm -rf XSStrike || true
  git clone --depth=1 https://github.com/s0md3v/XSStrike.git && cd XSStrike || err "clone XSStrike"
  python3 -m pip install --user -r requirements.txt || warn "reqs XSStrike"
  $SUDO ln -sf "$PWD/xsstrike.py" /usr/local/bin/xsstrike && $SUDO chmod +x /usr/local/bin/xsstrike
fi

# 7) commix (Git)
if command -v commix >/dev/null; then say "commix ya instalado"; else
  say "Instalando commix desde Git"
  cd "$TOOLS_DIR" && rm -rf commix || true
  git clone --depth=1 https://github.com/commixproject/commix.git && cd commix || err "clone commix"
  python3 -m pip install --user -r requirements.txt 2>/dev/null || true
  $SUDO ln -sf "$PWD/commix.py" /usr/local/bin/commix && $SUDO chmod +x /usr/local/bin/commix
fi

# 8) hydra (APT o compilar)
if command -v hydra >/dev/null; then say "hydra ya instalado"; else
  say "Instalando hydra por APT"; if ! APT_INSTALL hydra; then
    warn "APT falló. Compilando hydra (thc-hydra) desde Git"
    APT_INSTALL libssh-dev libidn11-dev libpcre3-dev libgcrypt20-dev libgpg-error-dev zlib1g-dev libpq-dev libsvn-dev libssl-dev || true
    cd "$TOOLS_DIR" && rm -rf thc-hydra || true
    git clone --depth=1 https://github.com/vanhauser-thc/thc-hydra.git && cd thc-hydra || err "clone hydra"
    ./configure || true
    make -j"$(nproc)" && $SUDO make install || err "hydra build/install falló"
  fi
fi

# 9) medusa (APT o compilar)
if command -v medusa >/dev/null; then say "medusa ya instalado"; else
  say "Instalando medusa por APT"; if ! APT_INSTALL medusa; then
    warn "APT falló. Compilando medusa desde Git"
    APT_INSTALL libssh2-1-dev libpq-dev libsvn-dev libssl-dev zlib1g-dev || true
    cd "$TOOLS_DIR" && rm -rf medusa || true
    git clone --depth=1 https://github.com/jmk-foofus/medusa.git && cd medusa || err "clone medusa"
    ./configure || true
    make -j"$(nproc)" && $SUDO make install || err "medusa build/install falló"
  fi
fi

# 10) dnsrecon (Git + pip)
if command -v dnsrecon >/dev/null; then say "dnsrecon ya instalado"; else
  say "Instalando dnsrecon desde Git"
  cd "$TOOLS_DIR" && rm -rf dnsrecon || true
  git clone --depth=1 https://github.com/darkoperator/dnsrecon.git && cd dnsrecon || err "clone dnsrecon"
  python3 -m pip install --user -r requirements.txt || warn "reqs dnsrecon"
  $SUDO ln -sf "$PWD/dnsrecon.py" /usr/local/bin/dnsrecon && $SUDO chmod +x /usr/local/bin/dnsrecon
fi

# 11) goldeneye (Git)
if command -v goldeneye >/dev/null; then say "goldeneye ya instalado"; else
  say "Instalando GoldenEye desde Git"
  cd "$TOOLS_DIR" && rm -rf GoldenEye || true
  git clone --depth=1 https://github.com/jseidl/GoldenEye.git && cd GoldenEye || err "clone GoldenEye"
  $SUDO ln -sf "$PWD/goldeneye.py" /usr/local/bin/goldeneye && $SUDO chmod +x /usr/local/bin/goldeneye
fi

# 12) metasploit (opcional, script oficial)
if command -v msfconsole >/dev/null; then say "metasploit ya instalado"; else
  warn "Instalando Metasploit (opcional). Esto tarda y añade repos de Rapid7."
  # Script oficial de Rapid7 (metasploit-omnibus)
  # Referencia: https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/
  if curl -fsSL -L https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o /tmp/msfinstall; then
    chmod 755 /tmp/msfinstall && $SUDO /tmp/msfinstall || warn "msfinstall: ejecución falló"
  else
    warn "Descarga de msfinstall falló. Probando vía Snap (opcional)."
    if command -v snap >/dev/null 2>&1; then
      $SUDO snap install metasploit-framework || warn "Snap metasploit-framework falló"
    else
      warn "snapd no está instalado. Para intentar Snap: sudo apt-get install -y snapd && sudo snap install metasploit-framework"
    fi
  fi
fi

say "Verificación final:"
for b in nmap hping3 slowhttptest nikto sqlmap xsstrike commix hydra medusa dnsrecon goldeneye msfconsole; do
  command -v "$b" >/dev/null && echo " - $b: OK" || echo " - $b: NO"
done