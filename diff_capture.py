#!/usr/bin/env python3
"""Diff a saved datapoint capture against the device's current state.

Two uses, both of which came up while chasing a stuck capacity setting:

  * After an unverified write, confirm that nothing OTHER than the intended
    field moved. A blind `property.set` into an unknown property namespace
    could in principle land somewhere unintended, and the only way to know is
    to compare every one of the 182 datapoints against a pre-write capture.

  * Across a regeneration, see exactly which fields the cycle touches. That is
    the ground truth for whether a capacity change took effect: the reset value
    of `capacity_remaining_tank_1` is decided by the controller, not by what a
    datapoint happens to report.

Captures are written by set_capacity.py as capacity-before-<stamp>.json.

    python diff_capture.py capacity-before-20260828-233544.json
    python diff_capture.py before.json --against after.json   # two files, no network

Stdlib only. Read-only -- sends no commands.
"""

from __future__ import annotations

import argparse
import getpass
import json
import ssl
import sys
import urllib.error
import urllib.request

BASE = "https://uniapi.culliganiot.com"
UA = "okhttp/4.12.0"
APP_ID = "OAhRjZjfBSwKLV8MTCjscAdoyJKzjxQW"

# Fields that move on their own every poll. Noise, not signal -- listing them
# separately keeps the real changes readable.
EXPECTED_DRIFT = {
    "current_flow_rate", "rssi", "time_rem_in_position",
    "total_water_usage_today_tank_1", "total_water_usage_today_tank_2",
    "total_water_usage_since_install_tank_1",
    "total_water_usage_since_install_tank_2",
    "capacity_remaining_tank_1", "capacity_remaining_tank_2",
    "away_mode_water_use", "days_salt_remaining",
    "manual_salt_level_rem_calc",
}


def call(method, path, body=None, token=None, timeout=25):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout,  # noqa: S310
                                    context=ssl.create_default_context()) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            return e.code, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return e.code, {"raw": raw[:400].decode("utf-8", "replace")}
    except urllib.error.URLError as e:
        return 0, {"transport_error": str(e.reason)}


def fetch_live(email: str) -> dict:
    password = getpass.getpass("Culligan password (not echoed, not stored): ")
    st, body = call("POST", "/api/v1/auth/login",
                    {"email": email, "password": password, "appId": APP_ID})
    del password
    if st != 200 or not body.get("success"):
        print(f"login failed: HTTP {st} {body}", file=sys.stderr)
        raise SystemExit(1)
    token = body["data"]["accessToken"]

    st, body = call("GET", "/api/v1/device/registry", token=token)
    devices = body.get("data", {}).get("devices", [])
    if not devices:
        print("no devices on this account", file=sys.stderr)
        raise SystemExit(1)
    serial = devices[0]["serialNumber"]

    st, body = call("GET", f"/api/v1/device/data?serialNumber={serial}",
                    token=token)
    if st != 200:
        print(f"telemetry read failed: HTTP {st}", file=sys.stderr)
        raise SystemExit(1)
    return body.get("data", {}).get("datapoints", {})


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        blob = json.load(fh)
    # Accept either a set_capacity.py capture or a bare datapoint dict.
    return blob.get("datapoints", blob)


def report(before: dict, after: dict) -> None:
    keys = sorted(set(before) | set(after))
    changed, drifted, appeared, vanished = [], [], [], []

    for k in keys:
        if k not in before:
            appeared.append((k, after[k]))
        elif k not in after:
            vanished.append((k, before[k]))
        elif before[k] != after[k]:
            (drifted if k in EXPECTED_DRIFT else changed).append(
                (k, before[k], after[k]))

    print(f"\n=== changed ({len(changed)}) ===")
    if changed:
        for k, b, a in changed:
            print(f"  {k:<44} {b}  ->  {a}")
    else:
        print("  nothing outside the expected-drift set moved.")

    if drifted:
        print(f"\n=== expected drift ({len(drifted)}) ===")
        for k, b, a in drifted:
            print(f"  {k:<44} {b}  ->  {a}")

    for label, rows in (("appeared", appeared), ("vanished", vanished)):
        if rows:
            print(f"\n=== {label} ({len(rows)}) ===")
            for k, v in rows:
                print(f"  {k:<44} {v}")

    # The one comparison this whole exercise turns on.
    cap = "capacity_remaining_tank_1"
    if cap in after:
        try:
            val = float(str(after[cap]).strip())
        except (TypeError, ValueError):
            return
        print(f"\n=== the number that decides it ===")
        print(f"  {cap} = {val:g}")
        if val > 0:
            print("  POSITIVE -- the controller now has usable capacity.")
            print("  The capacity fault is resolved; nightly cycling should stop.")
        else:
            print("  Still negative -- the unit remains permanently exhausted.")
            print("  If a regeneration has completed since the capture, the")
            print("  capacity figure the controller uses did not change.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("before", help="saved capture, e.g. capacity-before-*.json")
    ap.add_argument("--against", help="second file; omit to fetch live state")
    ap.add_argument("--email", help="Culligan account email (prompted if omitted)")
    args = ap.parse_args()

    before = load(args.before)
    print(f"before: {args.before}  ({len(before)} datapoints)")

    if args.against:
        after = load(args.against)
        print(f"after : {args.against}  ({len(after)} datapoints)")
    else:
        email = args.email or input("Culligan account email: ").strip()
        after = fetch_live(email)
        print(f"after : live  ({len(after)} datapoints)")

    report(before, after)
    return 0


if __name__ == "__main__":
    sys.exit(main())
