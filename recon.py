#!/usr/bin/env python3
"""
Culligan Smart HE - LAN recon.

Goal: find the softener's Wi-Fi module on the LAN and determine whether it
exposes an Ayla "Local Connect" (LAN mode) HTTP server.

If LAN mode is enabled in the device template, the module answers unauthenticated
GET /status.json with its DSN. That single response is the whole ballgame:
it means local control is reachable without the cloud.

Stdlib only. Run it on the same subnet as the softener:
    python recon.py
    python recon.py --host 192.168.1.57      # skip discovery, probe one IP
"""

import argparse
import concurrent.futures as cf
import ipaddress
import json
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request

# Ayla's embedded agent runs on ESP32 for recent designs, and the newer Culligan
# model number (AY008ESP1) carries an "ESP" suffix. An Espressif OUI on the LAN is
# therefore a strong first guess. Partial list of Espressif prefixes.
ESPRESSIF_OUIS = set(
    """
    083af2 0cb815 105210 10521c 18fe34 2462ab 240ac4 246f28 2c3ae8 30aea4
    30c6f7 348518 34ab95 3c6105 3c71bf 4022d8 441793 4831b7 483fda 4c11ae 4c7525
    4cebd6 543204 5443b2 58bf25 58cf79 58d349 5ccf7f 600194 64b708 686725
    68b6b3 68c63a 78e36d 7c2c67 7c87ce 7c9ebd 7cdfa1 807d3a 840d8e 84cca8
    84f703 8c4b14 8caab5 8cce4e a0204a a0764e a4cf12 a848fa ac0bfb ac67b2
    b0a732 b4e62d bcddc2 c049ef c44f33 c82b96 c8c9a3 c8db26 cc50e3 cc7b5c
    ccdba7 d0ef76 d4d4da d8a01d d8bc38 dc4f22 dc5475 e09806 e465b8 e831cd
    e86bea e8db84 ecfabc f008d1 f09e9e f412fa f4cfa2 fcf5c4
    """.split()
)
assert all(len(o) == 6 for o in ESPRESSIF_OUIS), "OUI list has a malformed entry"

# Endpoints exposed by the Ayla module's local HTTP server when LAN mode is on.
# /status.json is normally unauthenticated and is the definitive tell.
AYLA_PATHS = [
    "/status.json",
    "/local_reg.json",
    "/key_exchange.json",
    "/commands.json",
    "/property.json",
    "/regtoken.json",
    "/lanota.json",
]

CANDIDATE_PORTS = [80, 8888, 8080, 443, 8443, 5000, 10275]


def local_ipv4() -> str:
    """Best-effort primary IPv4 of this machine (no traffic actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
        return s.getsockname()[0]
    finally:
        s.close()


def arp_table() -> dict[str, str]:
    """Map IP -> normalized MAC from the OS ARP cache."""
    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=20
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}

    table = {}
    for line in out.splitlines():
        m = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})", line
        )
        if m:
            table[m.group(1)] = m.group(2).replace("-", "").replace(":", "").lower()
    return table


def warm_arp_cache(net: ipaddress.IPv4Network) -> None:
    """Touch every host so the ARP cache fills in. TCP connect is enough."""
    def touch(ip):
        for port in (80, 443, 8888):
            s = socket.socket()
            s.settimeout(0.35)
            try:
                s.connect((str(ip), port))
            except OSError:
                pass
            finally:
                s.close()

    hosts = list(net.hosts())
    with cf.ThreadPoolExecutor(max_workers=128) as pool:
        list(pool.map(touch, hosts))


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def probe_http(host: str, port: int, path: str, timeout: float = 4.0):
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
    ctx = None
    if scheme == "https":
        import ssl
        ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(4096)
    except urllib.error.HTTPError as e:
        return e.code, e.read(1024)
    except Exception:
        return None, None


def inspect(host: str) -> None:
    print(f"\n=== {host} ===")
    open_ports = [p for p in CANDIDATE_PORTS if port_open(host, p)]
    if not open_ports:
        print("  no candidate TCP ports open")
        return
    print(f"  open ports: {open_ports}")

    for port in open_ports:
        for path in AYLA_PATHS:
            status, body = probe_http(host, port, path)
            if status is None:
                continue
            snippet = (body or b"")[:300].decode("utf-8", "replace").strip()
            # A 404 from a real HTTP server still proves something is listening.
            marker = ""
            if status == 200 and b"dsn" in (body or b"").lower():
                marker = "   <-- AYLA LAN MODE CONFIRMED"
            print(f"  [{status}] :{port}{path}  {snippet[:180]!r}{marker}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", help="probe this IP only, skip discovery")
    ap.add_argument("--cidr", help="override subnet, e.g. 192.168.1.0/24")
    args = ap.parse_args()

    if args.host:
        inspect(args.host)
        return 0

    me = local_ipv4()
    net = ipaddress.IPv4Network(args.cidr or f"{me}/24", strict=False)
    print(f"this machine: {me}")
    print(f"sweeping {net} to populate ARP cache (~30s)...")
    warm_arp_cache(net)

    table = arp_table()
    print(f"{len(table)} hosts in ARP cache")

    espressif = {ip: mac for ip, mac in table.items() if mac[:6] in ESPRESSIF_OUIS}
    if espressif:
        print("\nEspressif-OUI hosts (likely candidates):")
        for ip, mac in sorted(espressif.items()):
            print(f"  {ip:<16} {mac}")
        targets = list(espressif)
    else:
        print("\nNo Espressif OUI found. Probing all ARP hosts instead.")
        print("(If the module isn't Espressif, match against your router's DHCP")
        print(" client list to spot the softener by lease name.)")
        targets = list(table)

    for ip in targets:
        if ip != me:
            inspect(ip)

    print("\nDone. A 200 on /status.json containing a DSN means LAN mode is live.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
