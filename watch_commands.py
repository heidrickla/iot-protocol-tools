"""Watch the capture for device/command POSTs and report each distinct verb once.

Request bodies are JSON-encoded *inside* each JSONL record, so a plain grep on the
raw file misses them -- they appear escaped. Parse properly instead.

    python watch_commands.py            # tail mode, prints new verbs as they appear
    python watch_commands.py --once     # print everything seen so far and exit
"""

import argparse
import json
import os
import sys
import time

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "mitm", "capture", "flows.jsonl")


def commands_in(path):
    """Yield (timestamp, command, params) for every device/command POST."""
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if rec.get("method") != "POST":
                    continue
                if "device/command" not in rec.get("path", ""):
                    continue
                try:
                    body = json.loads(rec.get("req_body") or "{}")
                except (json.JSONDecodeError, ValueError):
                    continue
                cmd = body.get("command")
                if cmd:
                    out.append((rec.get("ts", "")[:19], cmd, body.get("params", {})))
    except OSError:
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--timeout", type=int, default=14400)
    args = ap.parse_args()

    if args.once:
        seen = {}
        for ts, cmd, params in commands_in(LOG):
            seen.setdefault(cmd, []).append((ts, params))
        for cmd in sorted(seen):
            hits = seen[cmd]
            print(f"{cmd}  (x{len(hits)})")
            # Show distinct param shapes rather than every repeat.
            distinct = []
            for _, p in hits:
                s = json.dumps(p, sort_keys=True)
                if s not in distinct:
                    distinct.append(s)
            for s in distinct[:6]:
                print(f"     params: {s}")
        return 0

    known = {c for _, c, _ in commands_in(LOG)}
    print(f"watching; {len(known)} verb(s) already seen: {sorted(known)}", flush=True)
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        for ts, cmd, params in commands_in(LOG):
            if cmd not in known:
                known.add(cmd)
                print(f"*** NEW VERB *** {ts}  {cmd}  params={json.dumps(params)}",
                      flush=True)
        time.sleep(10)
    print("watch window elapsed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
