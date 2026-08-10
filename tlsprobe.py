#!/usr/bin/env python3
"""
TLS termination probe — the decisive test for this whole approach.

Once DNS points the softener's cloud hostname at this machine, the device will
open a TLS connection to us. The only question that matters:

    does the ESP32 validate the certificate?

  - Handshake COMPLETES  -> it does not validate. We can impersonate the cloud,
                            and everything it sends is ours to read. Path open.
  - Handshake REJECTED   -> it validates (or pins). Impersonation is dead and
                            the only remaining option is reflashing.

The probe presents a self-signed cert for the hostname and reports which
happened, distinguishing a genuine certificate rejection from an unrelated
protocol-negotiation failure — those look alike if you aren't careful, and
mistaking one for the other would give a false negative.

Run with the venv python (needs `cryptography`, already present via mitmproxy):

    venv\\Scripts\\python.exe tlsprobe.py --host uniapi.culliganiot.com
    venv\\Scripts\\python.exe tlsprobe.py --host X --port 443 --port 8883
    venv\\Scripts\\python.exe tlsprobe.py --host X --self-test
"""

import argparse
import datetime
import os
import socket
import ssl
import sys
import threading
import warnings

CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe-certs")

_lock = threading.Lock()
RESULTS = []


def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    with _lock:
        print(f"[{ts}] {msg}", flush=True)


def _cert_via_openssl(hostnames, crt_path, key_path):
    """Fallback cert generation using the openssl CLI.

    Lets the probe run on a bare VM with nothing but python3 + openssl, which
    matters when the listener has to live on the IoT VLAN rather than here.
    Returns True on success.
    """
    import shutil
    import subprocess

    if not shutil.which("openssl"):
        return False
    san = ",".join(f"DNS:{h}" for h in hostnames)
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", crt_path,
        "-days", "825", "-nodes",
        "-subj", f"/CN={hostnames[0]}",
        "-addext", f"subjectAltName={san}",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=90)
    except (OSError, subprocess.SubprocessError):
        return False
    if r.returncode != 0:
        log(f"openssl failed: {r.stderr.decode('utf-8', 'replace')[:300]}")
        return False
    return os.path.exists(crt_path) and os.path.exists(key_path)


def ensure_cert(hostnames, force_openssl=False):
    """Generate (once) a self-signed cert covering every name in `hostnames`.

    All candidates go in the SAN list so a name mismatch can never be the reason
    a handshake fails -- otherwise a rejection would be ambiguous between "wrong
    hostname on the cert" and "device validates the chain", which is precisely
    the distinction this probe exists to make.
    """
    hostname = hostnames[0]
    os.makedirs(CERT_DIR, exist_ok=True)
    crt_path = os.path.join(CERT_DIR, f"{hostname}.crt")
    key_path = os.path.join(CERT_DIR, f"{hostname}.key")
    if os.path.exists(crt_path) and os.path.exists(key_path):
        return crt_path, key_path

    if force_openssl:
        if _cert_via_openssl(hostnames, crt_path, key_path):
            log(f"generated self-signed cert for {hostname} (openssl)")
            return crt_path, key_path
        print("error: --force-openssl set but openssl generation failed",
              file=sys.stderr)
        raise SystemExit(2)

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        if _cert_via_openssl(hostnames, crt_path, key_path):
            log(f"generated self-signed cert for {hostname} (openssl fallback)")
            return crt_path, key_path
        print(
            "error: neither `cryptography` nor the openssl CLI is available.\n"
            "Install one:  pip install cryptography   |   apt install openssl",
            file=sys.stderr,
        )
        raise SystemExit(2)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    # Naive UTC: what x509.CertificateBuilder expects, without the utcnow() warning.
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    log(f"generated self-signed cert for {hostname}")
    return crt_path, key_path


def make_context(crt, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    # Be maximally permissive on version and cipher. An ESP32 running mbedTLS
    # may only offer TLS 1.2 and older suites; refusing those would surface as a
    # handshake failure and be misread as certificate rejection. We want the
    # ONLY reason a handshake can fail here to be the certificate itself.
    with warnings.catch_warnings():
        # TLSv1 as a floor is deprecated in modern Python, but deliberate here:
        # rejecting an old-but-working ESP32 handshake would read as a cert
        # failure and produce exactly the false negative this probe must avoid.
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except ssl.SSLError:
            pass
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def identify(data: bytes) -> str:
    if not data:
        return "no application data"
    if data[:1] == b"\x10":
        return "MQTT CONNECT"
    for verb in (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"PATCH ", b"DELETE "):
        if data.startswith(verb):
            return "HTTP request"
    if data[:1] == b"{":
        return "JSON payload"
    return "unrecognised binary"


def dump(data: bytes, limit: int = 512) -> str:
    out = []
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"    {i:04x}  {hexs}  {text}")
    if len(data) > limit:
        out.append(f"    ... +{len(data) - limit} more bytes")
    return "\n".join(out)


def handle(conn, addr, ctx):
    peer = f"{addr[0]}:{addr[1]}"
    log(f"TCP connect from {peer}")

    seen_sni = {}

    def sni_cb(sock, server_name, _ctx):
        # Fires mid-handshake, so we capture the requested hostname even when
        # the client subsequently rejects our certificate.
        seen_sni["name"] = server_name
        log(f"  SNI from {addr[0]}: {server_name}")

    ctx.sni_callback = sni_cb
    conn.settimeout(20)

    try:
        tls = ctx.wrap_socket(conn, server_side=True)
    except ssl.SSLError as e:
        reason = getattr(e, "reason", None) or str(e)
        verdict = "CERT REJECTED" if _is_cert_rejection(reason) else "handshake failed"
        log(f"  {verdict}: {reason}")
        RESULTS.append(("rejected", addr[0], seen_sni.get("name"), reason))
        conn.close()
        return
    except (OSError, socket.timeout) as e:
        log(f"  connection dropped before handshake completed: {e}")
        RESULTS.append(("dropped", addr[0], seen_sni.get("name"), str(e)))
        return

    log(f"  *** HANDSHAKE COMPLETED *** {tls.version()} / {tls.cipher()[0]}")
    log("  -> device does NOT validate certificates. Impersonation is viable.")
    RESULTS.append(("accepted", addr[0], seen_sni.get("name"), tls.version()))

    try:
        data = tls.recv(8192)
    except (ssl.SSLError, OSError, socket.timeout):
        data = b""

    if data:
        log(f"  received {len(data)} bytes — looks like: {identify(data)}")
        print(dump(data), flush=True)
    else:
        log("  no application data sent (device may be waiting on us to speak first)")

    try:
        tls.close()
    except OSError:
        pass


def _is_cert_rejection(reason: str) -> bool:
    r = (reason or "").upper()
    return any(
        k in r
        for k in (
            "UNKNOWN_CA", "BAD_CERTIFICATE", "CERTIFICATE_UNKNOWN",
            "CERTIFICATE_REQUIRED", "CERTIFICATE_EXPIRED", "DECRYPT_ERROR",
            "CERTIFICATE_REVOKED", "UNSUPPORTED_CERTIFICATE", "ACCESS_DENIED",
        )
    )


def serve(port, ctx):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except OSError as e:
        log(f"cannot bind :{port} ({e})")
        return
    srv.listen(8)
    log(f"listening on 0.0.0.0:{port}")
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            return
        threading.Thread(
            target=handle, args=(conn, addr, ctx), daemon=True
        ).start()


def self_test(hostname, port):
    """Prove the server works by connecting to it with a non-verifying client."""
    import time

    time.sleep(1.5)
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=8) as raw:
            with c.wrap_socket(raw, server_hostname=hostname) as t:
                t.sendall(b"GET /status.json HTTP/1.1\r\nHost: " +
                          hostname.encode() + b"\r\n\r\n")
                time.sleep(0.7)
        log("self-test client finished")
    except Exception as e:
        log(f"self-test client error: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, action="append", default=[],
                    help="hostname to impersonate (repeatable; all land in the "
                         "cert SAN, and SNI reveals which one the device wants)")
    ap.add_argument("--port", type=int, action="append", default=[],
                    help="port to listen on (repeatable; default 443)")
    ap.add_argument("--self-test", action="store_true",
                    help="connect to ourselves to verify the rig works")
    ap.add_argument("--force-openssl", action="store_true",
                    help="generate the cert via the openssl CLI even if "
                         "`cryptography` is installed (deployment testing)")
    args = ap.parse_args()

    ports = args.port or [443]
    crt, key = ensure_cert(args.host, force_openssl=args.force_openssl)
    ctx = make_context(crt, key)

    print("\nImpersonating: " + ", ".join(args.host))
    print("Waiting for the softener to connect. This requires the DNS redirect")
    print("to be active, pointing that hostname at this machine.\n")

    for p in ports:
        threading.Thread(target=serve, args=(p, ctx), daemon=True).start()

    if args.self_test:
        threading.Thread(target=self_test, args=(args.host[0], ports[0]),
                         daemon=True).start()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n=== verdict ===")
        if not RESULTS:
            print("  no connections received.")
            print("  Check the DNS redirect is live and the firewall allows inbound.")
        for outcome, ip, sni, detail in RESULTS:
            print(f"  {outcome:<9} {ip:<15} sni={sni or '-'}  {detail}")
        accepted = sum(1 for r in RESULTS if r[0] == "accepted")
        if accepted:
            print(f"\n  {accepted} handshake(s) completed -> impersonation VIABLE.")
        elif RESULTS:
            print("\n  All connections rejected -> device validates certificates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
