#!/usr/bin/env python3
"""
Logging DNS forwarder — the first half of the cloud-impersonation rig.

Two modes, and the default is deliberately harmless:

  observe (default)  Log every query, forward everything upstream unchanged.
                     Nothing breaks. This is how we learn the softener's cloud
                     hostname without touching its behaviour.

  hijack             Same, but answer the configured hostnames with our own IP
                     so the device connects to us instead of the cloud.

Run observe first, confirm the hostname, then flip to hijack.

    python dnsproxy.py --watch 192.0.2.50
    python dnsproxy.py --watch 192.0.2.50 --hijack uniapi.culliganiot.com=192.0.2.10

Binds UDP 53. Windows does not reserve low ports for admin, but the firewall
will likely need an inbound allow for UDP 53 (see the note printed at startup).
Stdlib only.
"""

import argparse
import ipaddress
import socket
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT",
              28: "AAAA", 33: "SRV", 65: "HTTPS"}

_print_lock = threading.Lock()


def log(msg: str, highlight: bool = False) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    with _print_lock:
        if highlight:
            print(f"[{ts}] {msg}", flush=True)
        else:
            print(f"[{ts}] {msg}", flush=True)


def parse_question(msg: bytes):
    """Return (qname, qtype, end_offset) for the first question, or None."""
    if len(msg) < 12:
        return None
    qdcount = struct.unpack("!H", msg[4:6])[0]
    if qdcount < 1:
        return None

    labels, off = [], 12
    while True:
        if off >= len(msg):
            return None
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:  # compression pointer -- not valid in a question
            return None
        off += 1
        if off + ln > len(msg):
            return None
        labels.append(msg[off:off + ln].decode("ascii", "replace"))
        off += ln

    if off + 4 > len(msg):
        return None
    qtype = struct.unpack("!H", msg[off:off + 2])[0]
    return ".".join(labels), qtype, off + 4


def build_a_response(query: bytes, qend: int, ip: str, ttl: int = 30) -> bytes:
    """Craft an A-record answer reusing the query's question section."""
    txid = query[:2]
    # QR=1, RD copied from query, RA=1
    rd = query[2] & 0x01
    flags = 0x8000 | (rd << 8) | 0x0080
    header = txid + struct.pack("!HHHHH", flags, 1, 1, 0, 0)
    question = query[12:qend]
    answer = (
        b"\xc0\x0c"                       # pointer to the question's name
        + struct.pack("!HHIH", 1, 1, ttl, 4)
        + socket.inet_aton(ip)
    )
    return header + question + answer


def forward(query: bytes, upstream: str, timeout: float = 4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (upstream, 53))
        data, _ = s.recvfrom(4096)
        return data
    except OSError:
        return None
    finally:
        s.close()


class Proxy:
    def __init__(self, upstream, watch, hijack):
        self.upstream = upstream
        self.watch = set(watch)
        self.hijack = hijack          # {lowercase hostname: ip}
        self.seen = {}                # hostname -> hit count, watched clients only

    def handle(self, sock, data, addr):
        client = addr[0]
        parsed = parse_question(data)
        if parsed is None:
            resp = forward(data, self.upstream)
            if resp:
                sock.sendto(resp, addr)
            return

        qname, qtype, qend = parsed
        watched = client in self.watch or not self.watch
        tname = TYPE_NAMES.get(qtype, str(qtype))

        if watched:
            self.seen[qname] = self.seen.get(qname, 0) + 1
            first = self.seen[qname] == 1
            marker = "  <-- NEW" if first else ""
            log(f"{client:<15} {tname:<6} {qname}{marker}", highlight=first)

        target = self.hijack.get(qname.lower())
        if target and qtype == 1:  # only spoof A records
            log(f"  >>> HIJACK {qname} -> {target} (for {client})", highlight=True)
            sock.sendto(build_a_response(data, qend, target), addr)
            return

        resp = forward(data, self.upstream)
        if resp:
            sock.sendto(resp, addr)
        elif watched:
            log(f"  !!! upstream timeout for {qname}")

    def serve(self, bind_ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Deliberately NOT SO_REUSEADDR on Windows: there it permits binding a
        # port another process already holds, so a conflict silently produces
        # erratic delivery instead of an error. We want the loud failure.
        if not sys.platform.startswith("win"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_ip, port))
        pool = ThreadPoolExecutor(max_workers=32)
        log(f"listening on {bind_ip}:{port}, upstream {self.upstream}")
        if self.hijack:
            for h, ip in self.hijack.items():
                log(f"HIJACK ARMED: {h} -> {ip}", highlight=True)
        else:
            log("observe-only mode: all queries forwarded unchanged")
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                pool.submit(self.handle, sock, data, addr)
        except KeyboardInterrupt:
            log("shutting down")
            self.report()
        finally:
            sock.close()

    def report(self):
        if not self.seen:
            log("no queries observed from watched clients")
            return
        print("\n=== hostnames queried by watched clients ===")
        for name, count in sorted(self.seen.items(), key=lambda kv: -kv[1]):
            print(f"  {count:>5}  {name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--upstream", default="1.1.1.1")
    ap.add_argument(
        "--watch", action="append", default=[],
        help="client IP to log (repeatable). Omit to log everything.",
    )
    ap.add_argument(
        "--hijack", action="append", default=[],
        help="hostname=ip to spoof (repeatable). Omit for observe-only.",
    )
    args = ap.parse_args()

    hijack = {}
    for item in args.hijack:
        if "=" not in item:
            print(f"error: --hijack needs hostname=ip, got {item!r}", file=sys.stderr)
            return 2
        host, ip = item.split("=", 1)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"error: {ip!r} is not a valid IP", file=sys.stderr)
            return 2
        hijack[host.strip().lower()] = ip.strip()

    print("If no queries arrive, Windows Firewall is probably dropping them.")
    print("Allow inbound UDP 53 (needs an elevated shell):")
    print('  netsh advfirewall firewall add rule name="dnsproxy" '
          "dir=in action=allow protocol=UDP localport=53\n")

    try:
        Proxy(args.upstream, args.watch, hijack).serve(args.bind, args.port)
    except PermissionError:
        print(f"error: cannot bind {args.bind}:{args.port}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: bind failed ({e}). Is something already on port 53?",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
