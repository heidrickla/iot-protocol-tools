"""
mitmproxy addon: capture and inventory the Culligan Connect app's API surface.

Two jobs:
  1. Log every Culligan/Ayla flow to JSONL so we can replay and model the API.
  2. Watch for the one thing that actually matters -- the app talking directly
     to a private (RFC1918) address. That would be Ayla Local Connect in action
     and would prove local control is reachable. Flagged loudly if seen.

Usage (from D:\\PersonalProjects\\culligan-local):
    venv\\Scripts\\mitmdump.exe -s mitm\\culligan_addon.py --set confdir=mitm\\conf

Output lands in mitm\\capture\\:
    flows.jsonl      full request/response records, secrets intact
    api-summary.md   deduplicated endpoint inventory, secrets redacted
    LOCAL-HITS.txt   written only if LAN-mode traffic is observed

api-summary.md and LOCAL-HITS.txt are redacted and safe to share. flows.jsonl is
the raw capture and contains live auth tokens -- treat it like a password file.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
from collections import OrderedDict
from datetime import datetime, timezone

from mitmproxy import http
from mitmproxy.log import ALERT  # mitmproxy 11+ dropped ctx.log; use stdlib logging

log = logging.getLogger(__name__)

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "capture")

# Hosts worth keeping. Everything else is phone background noise.
INTERESTING_HOST = re.compile(
    r"(culligan|ayla|aylanetworks|culliganiot)", re.IGNORECASE
)

# Header/body keys whose values must never reach the shareable summary.
SECRET_KEYS = re.compile(
    r"^(authorization|auth_token|access_token|refresh_token|id_token|password|"
    r"api_key|apikey|x-api-key|secret|app_secret|client_secret|setup_token|"
    r"cookie|set-cookie)$",
    re.IGNORECASE,
)

# Path segments that are identifiers rather than route structure.
DSN_RE = re.compile(r"^(AC|AY)[0-9A-Za-z]{10,}$")
HEXID_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def is_private_host(host: str) -> bool:
    """True if host is an RFC1918 / link-local address or resolves to one."""
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.gethostbyname(host)).is_private
    except (OSError, ValueError):
        return False


def normalize_path(path: str) -> str:
    """Collapse identifiers so /devices/AY008.../properties dedupes to one route."""
    out = []
    for seg in path.split("?")[0].split("/"):
        if not seg:
            out.append(seg)
        elif seg.isdigit():
            out.append("{id}")
        elif DSN_RE.match(seg):
            out.append("{dsn}")
        elif UUID_RE.match(seg):
            out.append("{uuid}")
        elif HEXID_RE.match(seg):
            out.append("{hex}")
        else:
            out.append(seg)
    return "/".join(out)


def redact(obj, depth: int = 0):
    """Recursively blank secret-looking values. Depth-capped against cycles."""
    if depth > 12:
        return "<...>"
    if isinstance(obj, dict):
        return {
            k: ("<REDACTED>" if SECRET_KEYS.match(str(k)) else redact(v, depth + 1))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(v, depth + 1) for v in obj[:8]]
    if isinstance(obj, str) and len(obj) > 400:
        return obj[:400] + f"<+{len(obj) - 400} bytes>"
    return obj


def scrub_text(text: str) -> str:
    """Blank secrets in a raw body. Prefers structured redaction; falls back to
    a regex pass so non-JSON bodies (form posts, XML) are still safe to share."""
    if not text:
        return text
    try:
        return json.dumps(redact(json.loads(text)))
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
    return re.sub(
        r'(?i)\b(auth_token|access_token|refresh_token|id_token|password|'
        r'api_?key|secret|token)\b(["\']?\s*[:=]\s*["\']?)([^"\'&,\s}]+)',
        r"\1\2<REDACTED>",
        text,
    )


def parse_body(raw: bytes):
    """Return (parsed_json_or_None, text_fallback)."""
    if not raw:
        return None, ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, f"<binary {len(raw)} bytes>"
    try:
        return json.loads(text), text
    except (json.JSONDecodeError, ValueError):
        return None, text


def shape(value, depth: int = 0):
    """Describe JSON structure without leaking values -- the useful bit for
    modelling an API. {"salt_level": 42} becomes {"salt_level": "int"}."""
    if depth > 6:
        return "..."
    if isinstance(value, dict):
        return {k: shape(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, list):
        return [shape(value[0], depth + 1)] if value else []
    if value is None:
        return "null"
    return type(value).__name__


class CulliganCapture:
    def __init__(self) -> None:
        os.makedirs(OUT_DIR, exist_ok=True)
        self.flows_path = os.path.join(OUT_DIR, "flows.jsonl")
        self.flows_fp = open(self.flows_path, "a", encoding="utf-8")
        self.endpoints: OrderedDict[tuple, dict] = OrderedDict()
        self.local_hits: list[dict] = []
        self.hosts: set[str] = set()
        self.count = 0

    # -- mitmproxy hooks ---------------------------------------------------

    def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        local = is_private_host(host)

        # Keep anything Culligan-shaped, plus *all* local traffic. A LAN-mode
        # device may answer on a bare IP with no recognisable hostname, so the
        # host regex alone would miss exactly the case we care most about.
        if not (INTERESTING_HOST.search(host) or local):
            return

        self.count += 1
        self.hosts.add(host)

        req_json, req_text = parse_body(flow.request.raw_content or b"")
        res_json, res_text = parse_body(flow.response.raw_content or b"")

        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": host,
            "port": flow.request.port,
            "path": flow.request.path,
            "private_ip": local,
            "req_headers": dict(flow.request.headers),
            "req_body": req_text[:20000],
            "status": flow.response.status_code,
            "res_headers": dict(flow.response.headers),
            "res_body": res_text[:20000],
        }
        self.flows_fp.write(json.dumps(record) + "\n")
        self.flows_fp.flush()

        if local:
            self.local_hits.append(record)
            log.log(
                ALERT,
                f"*** LOCAL TRAFFIC: {flow.request.method} {host}:{flow.request.port}"
                f"{flow.request.path} -> {flow.response.status_code} ***",
            )

        key = (flow.request.method, host, normalize_path(flow.request.path))
        entry = self.endpoints.setdefault(
            key,
            {
                "hits": 0,
                "statuses": set(),
                "req_shape": None,
                "res_shape": None,
                "sample_res": None,
                "private": local,
            },
        )
        entry["hits"] += 1
        entry["statuses"].add(flow.response.status_code)
        if entry["req_shape"] is None and req_json is not None:
            entry["req_shape"] = shape(req_json)
        if entry["res_shape"] is None and res_json is not None:
            entry["res_shape"] = shape(res_json)
            entry["sample_res"] = redact(res_json)

        if self.count % 10 == 0:
            log.info(f"[culligan] {self.count} flows captured")

        # Reports are rewritten as we go rather than only at shutdown: mitmdump
        # does not reliably run done() when killed or Ctrl+C'd on Windows, and
        # losing the summary after a long capture would be painful. Volumes here
        # are small (hundreds of flows at most), so the rewrite cost is noise.
        if local or self.count % 5 == 0:
            self._flush_reports()

    def done(self) -> None:
        self._flush_reports()
        try:
            self.flows_fp.close()
        except Exception:
            pass

    def _flush_reports(self) -> None:
        try:
            self._write_summary()
            if self.local_hits:
                self._write_local_hits()
        except Exception as exc:  # never let reporting kill the capture
            log.warning(f"[culligan] report write failed: {exc}")

    # -- reporting ---------------------------------------------------------

    def _write_summary(self) -> None:
        lines = [
            "# Culligan API surface (observed)",
            "",
            f"Captured {self.count} flows across {len(self.hosts)} hosts.",
            "",
            "## Hosts",
            "",
        ]
        for h in sorted(self.hosts):
            tag = "  **[PRIVATE IP -- LAN MODE]**" if is_private_host(h) else ""
            lines.append(f"- `{h}`{tag}")

        lines += ["", "## Endpoints", ""]
        for (method, host, path), e in self.endpoints.items():
            flag = "  **[LOCAL]**" if e["private"] else ""
            statuses = ",".join(str(s) for s in sorted(e["statuses"]))
            lines.append(f"### `{method} {host}{path}`{flag}")
            lines.append("")
            lines.append(f"- hits: {e['hits']} | statuses: {statuses}")
            if e["req_shape"]:
                lines.append("- request shape:")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(e["req_shape"], indent=2)[:2000])
                lines.append("```")
            if e["res_shape"]:
                lines.append("- response shape:")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(e["res_shape"], indent=2)[:2000])
                lines.append("```")
            if e["sample_res"] is not None:
                lines.append("- sample response (redacted):")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(e["sample_res"], indent=2)[:2500])
                lines.append("```")
            lines.append("")

        path = os.path.join(OUT_DIR, "api-summary.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        log.log(ALERT, f"[culligan] wrote {path}")

    def _write_local_hits(self) -> None:
        path = os.path.join(OUT_DIR, "LOCAL-HITS.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "LAN-mode traffic observed. The app talked directly to a private\n"
                "address, so local control is reachable without the cloud.\n\n"
            )
            for r in self.local_hits:
                f.write(
                    f"{r['method']} {r['host']}:{r['port']}{r['path']} "
                    f"-> {r['status']}\n"
                )
                if r["req_body"]:
                    f.write(f"  req: {scrub_text(r['req_body'])[:600]}\n")
                if r["res_body"]:
                    f.write(f"  res: {scrub_text(r['res_body'])[:600]}\n")
                f.write("\n")
        log.log(ALERT, f"[culligan] *** {path} -- LAN MODE CONFIRMED ***")


addons = [CulliganCapture()]
