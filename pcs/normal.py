#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generador de tráfico "normal" para entrenamiento.
Simula navegación web, DNS, pings al gateway, consultas a repos, y tráfico interno.
Solo usa dominios y endpoints seguros. Salida controlada y con jitter.
"""
#python3 normal.py --gw 192.168.10.1 --internal 192.168.10.1:8000
import argparse
import os
import random
import socket
import string
import subprocess
import threading
import time
from typing import List, Tuple

import requests
import io

# ----------------- utilidades -----------------

def jitter(base: float, spread: float = 0.5) -> float:
    return max(0.05, random.uniform(base * (1 - spread), base * (1 + spread)))


def log(ok: bool, msg: str):
    prefix = "✅" if ok else "❌"
    print(f"{prefix} {msg}")


def resolve_host(host: str, family=socket.AF_UNSPEC):
    try:
        socket.getaddrinfo(host, None, family)
        log(True, f"DNS {host}")
        return True
    except Exception as e:
        log(False, f"DNS {host} -> {e}")
        return False


def http_get(url: str, headers=None, timeout=5):
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        log(True, f"GET {url} {r.status_code}")
        return True
    except Exception as e:
        log(False, f"GET {url} -> {e}")
        return False


def http_head(url: str, headers=None, timeout=5):
    try:
        r = requests.head(url, headers=headers, timeout=timeout)
        log(True, f"HEAD {url} {r.status_code}")
        return True
    except Exception as e:
        log(False, f"HEAD {url} -> {e}")
        return False


def http_post(url: str, data: dict, headers=None, timeout=5):
    try:
        r = requests.post(url, data=data, headers=headers, timeout=timeout)
        log(True, f"POST {url} {r.status_code}")
        return True
    except Exception as e:
        log(False, f"POST {url} -> {e}")
        return False


def ping(host: str, count=1, timeout=2):
    cmd = f"ping -c {count} -W {timeout} {host}"
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        log(True, f"ICMP {host}")
        return True
    except subprocess.CalledProcessError:
        log(False, f"ICMP {host}")
        return False


# ----------------- listas de destinos -----------------

WEB_SITES: List[str] = [
    # Trabajo y desarrollo
    "https://github.com", "https://gitlab.com", "https://stackoverflow.com",
    "https://www.linkedin.com", "https://news.ycombinator.com",
    # Noticias
    "https://www.bbc.com", "https://elpais.com", "https://www.nytimes.com",
    # Compras consumo
    "https://www.amazon.com", "https://www.ebay.com",
    # Educación y doc
    "https://developer.mozilla.org", "https://www.python.org",
]

CDN_ASSETS: List[str] = [
    "/robots.txt", "/favicon.ico", "/", "/sitemap.xml"
]

DNS_HOSTS: List[str] = [
    "github.com", "cdn.cloudflare.com", "api.github.com", "pypi.org",
    "bbc.co.uk", "nytimes.com", "static.cloudflareinsights.com",
]

PKG_ENDPOINTS: List[str] = [
    "https://deb.debian.org/debian/",        # metadata
    "https://security.debian.org/debian-security/",
    "https://pypi.org/simple/requests/",     # índice simple
]

DOWNLOAD_ENDPOINTS: List[str] = [
    "https://httpbin.org/image/png",
    "https://httpbin.org/bytes/32768",          # 32 KiB aleatorios
    "https://www.python.org/static/img/python-logo.png",
]

# DNS over HTTPS (DoH)
DOH_ENDPOINTS: List[str] = [
    "https://cloudflare-dns.com/dns-query",     # Cloudflare DoH
    "https://dns.google/resolve",               # Google DoH
]

 # Probes TCP típicos de oficina (solo handshake TCP, sin credenciales)
TCP_PROBES: List[Tuple[str, int]] = [
    ("smtp.gmail.com", 587),
    ("imap.gmail.com", 993),
    ("outlook.office365.com", 993),
    ("smtp.office365.com", 587),
    ("time.cloudflare.com", 443),    # TLS handshake
    ("one.one.one.one", 853),        # DoT TCP/853
]

SAFE_POST: str = "https://httpbin.org/post"  # servicio de eco para POST benignos

# ----------------- hilos de tráfico -----------------

def browsing_loop(stop: threading.Event, ua: str, base_sleep: float):
    headers = {"User-Agent": ua}
    while not stop.is_set():
        # Selección de 3-6 sitios y 1-3 recursos por sitio
        session = random.sample(WEB_SITES, k=random.randint(3, min(6, len(WEB_SITES))))
        for site in session:
            if stop.is_set():
                break
            # HEAD inicial tipo precarga
            http_head(site, headers=headers, timeout=5)
            time.sleep(jitter(0.5, 0.7))
            # GET del home y algún asset común
            http_get(site, headers=headers, timeout=7)
            for _ in range(random.randint(1, 3)):
                path = random.choice(CDN_ASSETS)
                url = site.rstrip("/") + path
                http_get(url, headers=headers, timeout=7)
                time.sleep(jitter(0.6))
            # Algún POST benigno a httpbin
            payload = {"q": random.choice(["status", "ping", "search", "metrics"]) ,
                       "token": "".join(random.choices(string.ascii_letters+string.digits, k=6))}
            http_post(SAFE_POST, payload, headers=headers, timeout=5)
            wait = jitter(base_sleep)
            print(f"⏳ Pausa navegación {wait:.1f}s")
            stop.wait(wait)
        # Pausa larga simulando trabajo/lectura
        long_pause = jitter(base_sleep * 4, 0.6)
        print(f"💤 Pausa larga {long_pause:.1f}s")
        stop.wait(long_pause)


def dns_loop(stop: threading.Event, base_sleep: float):
    while not stop.is_set():
        host = random.choice(DNS_HOSTS)
        resolve_host(host)
        stop.wait(jitter(base_sleep * 0.7))


def icmp_loop(stop: threading.Event, gw: str, base_sleep: float):
    while not stop.is_set():
        ping(gw, count=1, timeout=2)
        stop.wait(jitter(base_sleep * 1.5))


def internal_loop(stop: threading.Event, internal_http: str, base_sleep: float):
    # Tráfico a servicios internos típicos (tu FastAPI, paneles, etc.)
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    while not stop.is_set():
        http_get(f"http://{internal_http}/", headers=headers, timeout=3)
        # Endpoint de salud si existe
        http_get(f"http://{internal_http}/health", headers=headers, timeout=3)
        stop.wait(jitter(base_sleep))


def packages_loop(stop: threading.Event, base_sleep: float):
    # Simula comprobaciones de repositorios de paquetes
    while not stop.is_set():
        url = random.choice(PKG_ENDPOINTS)
        http_head(url, timeout=5)
        stop.wait(jitter(base_sleep * 3))


def upload_loop(stop: threading.Event, base_sleep: float):
    # Subida de archivos pequeños a un endpoint seguro (httpbin echo)
    while not stop.is_set():
        size_kb = random.choice([8, 16, 32, 64])
        payload = io.BytesIO(os.urandom(size_kb * 1024)) if hasattr(os, 'urandom') else io.BytesIO(b"x" * size_kb * 1024)
        files = {"file": (f"report_{int(time.time())}.bin", payload)}
        try:
            r = requests.post(SAFE_POST, files=files, timeout=8)
            log(True, f"UPLOAD {size_kb}KB -> {r.status_code}")
        except Exception as e:
            log(False, f"UPLOAD -> {e}")
        stop.wait(jitter(base_sleep * 3))


def download_loop(stop: threading.Event, base_sleep: float):
    # Descargas ligeras simuladas
    while not stop.is_set():
        url = random.choice(DOWNLOAD_ENDPOINTS)
        try:
            r = requests.get(url, timeout=8, stream=True)
            # leer solo los primeros bytes para simular consumo
            _ = next(r.iter_content(chunk_size=4096), b"")
            log(True, f"DOWNLOAD {url} {r.status_code}")
        except Exception as e:
            log(False, f"DOWNLOAD {url} -> {e}")
        stop.wait(jitter(base_sleep * 2))


def doh_loop(stop: threading.Event, base_sleep: float):
    # Resolución DNS por DoH
    while not stop.is_set():
        endpoint = random.choice(DOH_ENDPOINTS)
        params = {"name": random.choice(["example.com","github.com","python.org"]), "type": "A"}
        headers = {"accept": "application/dns-json"}
        try:
            r = requests.get(endpoint, params=params, headers=headers, timeout=6)
            ok = r.ok
            log(ok, f"DoH {endpoint} {params['name']} -> {r.status_code}")
        except Exception as e:
            log(False, f"DoH {endpoint} -> {e}")
        stop.wait(jitter(base_sleep * 1.5))


def tcp_probe_loop(stop: threading.Event, base_sleep: float):
    # Handshake TCP a servicios comunes de ofimática
    while not stop.is_set():
        host, port = random.choice(TCP_PROBES)
        try:
            with socket.create_connection((host, port), timeout=4):
                log(True, f"TCP {host}:{port}")
        except Exception as e:
            log(False, f"TCP {host}:{port} -> {e}")
        stop.wait(jitter(base_sleep * 2))


# ----------------- main -----------------

def main():
    parser = argparse.ArgumentParser(description="Simulador de tráfico normal para entrenamiento")
    parser.add_argument("--gw", default="192.168.10.1", help="Gateway LAN para ICMP")
    parser.add_argument("--internal", default="192.168.10.1:8000", help="Host:puerto interno para HTTP")
    parser.add_argument("--base-sleep", type=float, default=4.0, help="Segundos base entre acciones")
    parser.add_argument("--duration", type=int, default=0, help="Duración total en segundos (0 = infinito)")
    parser.add_argument("--no-uploads", action="store_true", help="Desactiva subidas de ficheros benignas")
    parser.add_argument("--no-downloads", action="store_true", help="Desactiva descargas ligeras")
    parser.add_argument("--no-doh", action="store_true", help="Desactiva resoluciones DNS sobre HTTPS")
    parser.add_argument("--no-tcpprobes", action="store_true", help="Desactiva conexiones TCP a puertos comunes")
    args = parser.parse_args()

    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1_0) AppleWebKit/605.1.15 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/113.0",
    ]
    ua = random.choice(uas)

    stop = threading.Event()
    threads = [
        threading.Thread(target=browsing_loop, args=(stop, ua, args.base_sleep), daemon=True),
        threading.Thread(target=dns_loop, args=(stop, args.base_sleep), daemon=True),
        threading.Thread(target=icmp_loop, args=(stop, args.gw, args.base_sleep), daemon=True),
        threading.Thread(target=internal_loop, args=(stop, args.internal, args.base_sleep), daemon=True),
        threading.Thread(target=packages_loop, args=(stop, args.base_sleep), daemon=True),
        None if args.no_downloads else threading.Thread(target=download_loop, args=(stop, args.base_sleep), daemon=True),
        None if args.no_uploads else threading.Thread(target=upload_loop, args=(stop, args.base_sleep), daemon=True),
        None if args.no_doh else threading.Thread(target=doh_loop, args=(stop, args.base_sleep), daemon=True),
        None if args.no_tcpprobes else threading.Thread(target=tcp_probe_loop, args=(stop, args.base_sleep), daemon=True),
    ]
    threads = [t for t in threads if t is not None]

    print("🌐 Iniciando simulación de tráfico normal. Ctrl+C para salir.")
    for t in threads:
        t.start()

    try:
        if args.duration > 0:
            stop.wait(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2)
        print("✅ Simulación finalizada")


if __name__ == "__main__":
    main()