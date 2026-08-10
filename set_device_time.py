#!/usr/bin/env python3
"""
Set the Culligan softener's clock via the Culligan Connect cloud API.

The app has no UI for this, but the API supports it. Command shape taken from the
app's own AzureDeviceCommandFactory.setDateTime:

    command    timeDate.set
    param key  dateTimeValue
    format     M-d-yyyy_HH:mm:ss     (no leading zero on month/day, 24h clock)

Your password is read with getpass -- never echoed, never written to disk, never
logged. It is sent only to https://uniapi.culliganiot.com over TLS, which is where
the app sends it too.

    python set_device_time.py                      # dry run, shows what it would send
    python set_device_time.py --apply              # actually set the clock
    python set_device_time.py --apply --time "2026-08-10 09:52:00"

Stdlib only.
"""

import argparse
import datetime
import getpass
import json
import ssl
import sys
import urllib.error
import urllib.request
import uuid

BASE = "https://uniapi.culliganiot.com"
UA = "okhttp/4.12.0"


def call(method, path, body=None, token=None, timeout=25):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            return e.code, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return e.code, {"raw": raw[:300].decode("utf-8", "replace")}


def login(email, password, app_id):
    st, body = call("POST", "/api/v1/auth/login",
                    {"email": email, "password": password, "appId": app_id})
    if st != 200 or not body.get("success"):
        print(f"login failed: HTTP {st} {body}", file=sys.stderr)
        raise SystemExit(1)
    return body["data"]["accessToken"]


def list_devices(token):
    st, body = call("GET", "/api/v1/device/registry", token=token)
    if st != 200:
        print(f"registry failed: HTTP {st} {body}", file=sys.stderr)
        raise SystemExit(1)
    return body.get("data", {}).get("devices", [])


def make_request_id():
    ts = datetime.datetime.now().isoformat()
    return f"CC-{ts}-{uuid.uuid4().hex[:8]}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", help="Culligan account email (prompted if omitted)")
    # Constant the Android app sends with every login; captured 2026-08-10.
    ap.add_argument("--app-id", default="OAhRjZjfBSwKLV8MTCjscAdoyJKzjxQW",
                    help="appId sent at login (default: the Android app's)")
    ap.add_argument("--serial", help="device serial; auto-detected if you have one device")
    ap.add_argument("--time", help='target local time "YYYY-MM-DD HH:MM:SS" (default: now)')
    ap.add_argument("--apply", action="store_true",
                    help="actually send it. Without this, dry run only.")
    args = ap.parse_args()

    if args.time:
        try:
            target = datetime.datetime.strptime(args.time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            print('--time must look like "2026-08-10 09:52:00"', file=sys.stderr)
            return 2
    else:
        target = datetime.datetime.now().replace(microsecond=0)

    # Exactly the app's format: M-d-yyyy_HH:mm:ss, no zero padding on month/day.
    value = f"{target.month}-{target.day}-{target.year}_{target:%H:%M:%S}"

    print(f"target local time : {target}")
    print(f"dateTimeValue     : {value}")
    print()

    email = args.email or input("Culligan account email: ").strip()
    password = getpass.getpass("Culligan password (not echoed, not stored): ")

    print("\nauthenticating...")
    token = login(email, password, args.app_id)
    del password
    print("  ok")

    devices = list_devices(token)
    if not devices:
        print("no devices on this account", file=sys.stderr)
        return 1
    for d in devices:
        print(f"  device: {d.get('serialNumber')}  {d.get('name')}  ({d.get('model')})")

    serial = args.serial
    if not serial:
        if len(devices) > 1:
            print("multiple devices -- pass --serial", file=sys.stderr)
            return 2
        serial = devices[0]["serialNumber"]

    # Show the device's current idea of the date before changing anything.
    # NOTE: /device/data requires ?serialNumber= -- without it the call fails and
    # this whole section silently vanishes, which is exactly what it did at first.
    st, data = call("GET", f"/api/v1/device/data?serialNumber={serial}", token=token)
    if st == 200:
        dp = data.get("data", {}).get("datapoints", {})
        print("\ndevice currently reports:")
        for k in ("last_power_up_time", "last_regen_date_time_tank_1",
                  "next_regen_date_time", "installation_date"):
            if k in dp:
                print(f"  {k:<30} {dp[k]}")
    else:
        print(f"\n(could not read /device/data: HTTP {st})")

    payload = {
        "command": "timeDate.set",
        "params": {"dateTimeValue": value},
        "protocolVersion": 1,
        "requestId": make_request_id(),
        "serialNumber": serial,
    }
    print("\nwould POST /api/v1/device/command:")
    print(json.dumps(payload, indent=2))

    if not args.apply:
        print("\nDRY RUN -- nothing sent. Re-run with --apply to actually set the clock.")
        return 0

    print("\nsending...")
    st, body = call("POST", "/api/v1/device/command", payload, token=token)
    print(f"  HTTP {st}  {json.dumps(body)[:300]}")
    if st == 200 and body.get("success"):
        print("\nAccepted. The response only acknowledges the request -- it does not")
        print("confirm the device applied it. Re-check last_power_up_time or the app")
        print("in a few minutes to verify the clock actually moved.")
    else:
        print("\nRejected. The param name or format may differ for this model;")
        print("nothing was changed on the device.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
