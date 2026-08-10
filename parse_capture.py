#!/usr/bin/env python3
"""
Extract destination hostnames from a tcpdump capture of the softener.

Even though the softener's traffic is 100% TLS, the hostname is not secret:
  - DNS queries are plaintext UDP
  - the TLS SNI field in the ClientHello is plaintext

Both are enough to identify the cloud endpoint we need to impersonate.

Pure stdlib -- no scapy, no tshark, no Wireshark install needed.

    python parse_capture.py culligan.pcap

Handles classic pcap from `tcpdump -w`, Ethernet / Linux cooked (-i any) / raw.
"""

import argparse
import collections
import socket
import struct
import sys

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


def read_pcap(path):
    """Yield raw link-layer frames from a classic pcap file."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("file too short to be a pcap")

        magic = gh[:4]
        if magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"
        elif magic[:4] == b"\x0a\x0d\x0d\x0a":
            raise ValueError(
                "this is a pcapng file; capture with `tcpdump -w` "
                "(classic pcap) instead"
            )
        else:
            raise ValueError(f"unrecognised pcap magic: {magic.hex()}")

        linktype = struct.unpack(endian + "I", gh[20:24])[0]

        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            _, _, incl, _ = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield linktype, data


def strip_link(linktype, frame):
    """Return the IP payload, or None if this frame isn't IPv4."""
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        etype = struct.unpack("!H", frame[12:14])[0]
        off = 14
        # Walk any 802.1Q / QinQ tags -- the IoT traffic is VLAN-tagged.
        while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:
            etype = struct.unpack("!H", frame[off + 2 : off + 4])[0]
            off += 4
        return frame[off:] if etype == 0x0800 else None

    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        etype = struct.unpack("!H", frame[14:16])[0]
        return frame[16:] if etype == 0x0800 else None

    if linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        etype = struct.unpack("!H", frame[0:2])[0]
        return frame[20:] if etype == 0x0800 else None

    if linktype == LINKTYPE_RAW:
        return frame

    return None


def parse_ipv4(pkt):
    """Return (src, dst, proto, payload) or None."""
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if len(pkt) < ihl:
        return None
    total_len = struct.unpack("!H", pkt[2:4])[0]
    proto = pkt[9]
    src = socket.inet_ntoa(pkt[12:16])
    dst = socket.inet_ntoa(pkt[16:20])
    # Trust total_len when sane, so trailing padding isn't parsed as payload.
    end = total_len if 0 < total_len <= len(pkt) else len(pkt)
    return src, dst, proto, pkt[ihl:end]


def dns_names(payload):
    """Extract query names from a DNS message."""
    if len(payload) < 12:
        return []
    qdcount = struct.unpack("!H", payload[4:6])[0]
    if qdcount == 0 or qdcount > 32:
        return []

    names, off = [], 12
    for _ in range(qdcount):
        labels = []
        while True:
            if off >= len(payload):
                return names
            ln = payload[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:  # compression pointer; not expected in a question
                off += 2
                break
            off += 1
            if off + ln > len(payload):
                return names
            labels.append(payload[off : off + ln].decode("ascii", "replace"))
            off += ln
        if labels:
            names.append(".".join(labels))
        off += 4  # qtype + qclass
    return names


def tls_sni(payload):
    """Extract the SNI hostname from a TLS ClientHello, if present."""
    # TLS record: type(1) version(2) length(2)
    if len(payload) < 5 or payload[0] != 0x16:
        return None
    p = payload[5:]
    # Handshake: type(1) length(3) version(2) random(32)
    if len(p) < 38 or p[0] != 0x01:
        return None
    off = 38

    def need(n):
        return off + n <= len(p)

    if not need(1):
        return None
    off += 1 + p[off]  # session_id

    if not need(2):
        return None
    off += 2 + struct.unpack("!H", p[off : off + 2])[0]  # cipher_suites

    if not need(1):
        return None
    off += 1 + p[off]  # compression_methods

    if not need(2):
        return None
    ext_total = struct.unpack("!H", p[off : off + 2])[0]
    off += 2
    end = min(off + ext_total, len(p))

    while off + 4 <= end:
        etype, elen = struct.unpack("!HH", p[off : off + 4])
        off += 4
        if off + elen > end:
            return None
        if etype == 0x0000:  # server_name
            e = p[off : off + elen]
            if len(e) >= 5 and e[2] == 0x00:  # host_name
                nlen = struct.unpack("!H", e[3:5])[0]
                if 5 + nlen <= len(e):
                    return e[5 : 5 + nlen].decode("ascii", "replace")
            return None
        off += elen
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument(
        "--host", help="only report traffic involving this IP (e.g. 192.0.2.50)"
    )
    args = ap.parse_args()

    dns = collections.Counter()
    sni = collections.Counter()
    peers = collections.Counter()
    total = 0

    try:
        frames = read_pcap(args.pcap)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    for linktype, frame in frames:
        ip = strip_link(linktype, frame)
        if ip is None:
            continue
        parsed = parse_ipv4(ip)
        if parsed is None:
            continue
        src, dst, proto, payload = parsed

        if args.host and args.host not in (src, dst):
            continue
        total += 1

        if proto == 17 and len(payload) >= 8:  # UDP
            sport, dport = struct.unpack("!HH", payload[0:4])
            if 53 in (sport, dport):
                for n in dns_names(payload[8:]):
                    dns[n] += 1

        elif proto == 6 and len(payload) >= 20:  # TCP
            sport, dport = struct.unpack("!HH", payload[0:4])
            doff = (payload[12] >> 4) * 4
            if doff < 20 or len(payload) < doff:
                continue
            body = payload[doff:]
            if body:
                name = tls_sni(body)
                if name:
                    sni[name] += 1
            if args.host and src == args.host:
                peers[f"{dst}:{dport}"] += 1

    print(f"packets examined: {total}\n")

    print("=== DNS queries ===")
    if dns:
        for n, c in dns.most_common():
            print(f"  {c:>5}  {n}")
    else:
        print("  (none -- device may use hardcoded IPs or DNS-over-TLS/HTTPS)")

    print("\n=== TLS SNI hostnames ===")
    if sni:
        for n, c in sni.most_common():
            print(f"  {c:>5}  {n}")
    else:
        print("  (none -- no ClientHello captured, or SNI omitted/encrypted)")

    if peers:
        print("\n=== Outbound peers ===")
        for p, c in peers.most_common(20):
            print(f"  {c:>5}  {p}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
