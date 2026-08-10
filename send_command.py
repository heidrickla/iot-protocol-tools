#!/usr/bin/env python3
"""
Send any documented Culligan device command via the cloud API.

Dry-run by default. Password is read with getpass -- never echoed, never stored,
never logged; it goes only to https://uniapi.culliganiot.com over TLS.

    python send_command.py --list
    python send_command.py awayMode.alert.clear
    python send_command.py alarm.silence --params '{"days": 1}' --apply
    python send_command.py regen.set --params '{"type": 1}' --apply

Command/param shapes come from AzureDeviceCommandFactory in the decompiled app.
See API.md. Stdlib only.
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
APP_ID = "OAhRjZjfBSwKLV8MTCjscAdoyJKzjxQW"
UA = "okhttp/4.12.0"

# verb -> (default params, risk note). Risk notes are shown before --apply.
COMMANDS = {
    "telemetry.get":         ({}, None),
    "salt.set":              ({"level": 50}, "changes the reported salt level"),
    "salt.slm.set":          ({}, "may reset/recalibrate the salt level monitor"),
    "awayMode.set":          ({"active": 0}, "toggles vacation mode"),
    "awayMode.alert.clear":  ({}, None),
    "bypass.timed.on":       ({"duration": 30},
                              "BYPASSES SOFTENING for the duration - hard water to the house"),
    "bypass.permanent.on":   ({},
                              "BYPASSES SOFTENING INDEFINITELY until bypass.off"),
    "bypass.off":            ({}, None),
    "regen.set":             ({"type": 1},
                              "type 1 = regenerate NOW (uses salt and water); type 2 = schedule"),
    "timeDate.set":          (None, "sets the device clock; use set_device_time.py instead"),
    "alarm.silence":         ({"days": 1},
                              "MUTES ALL ALERTS for the given days. There is NO un-silence "
                              "command. The app hardcodes 7; this default is 1 to limit exposure."),
    "property.set":          (None, "generic property write; namespace unknown, Gbx2 only"),
}


def call(method, path, body=None, token=None, timeout=25):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl.create_default_context()) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            return e.code, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return e.code, {"raw": raw[:300].decode("utf-8", "replace")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", nargs="?", help="command verb, e.g. awayMode.alert.clear")
    ap.add_argument("--params", help='JSON params object, e.g. \'{"days": 1}\'')
    # PowerShell mangles embedded quotes in native-command args, so offer a
    # quote-free alternative: --set days=1 --set level=50
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="set one param without JSON quoting (repeatable). "
                         "Values that look numeric are sent as numbers.")
    ap.add_argument("--serial", help="device serial (auto-detected if you have one)")
    ap.add_argument("--email")
    ap.add_argument("--list", action="store_true", help="list known commands and exit")
    ap.add_argument("--apply", action="store_true", help="actually send it")
    args = ap.parse_args()

    if args.list or not args.command:
        print("known commands (default params shown):\n")
        for c, (p, risk) in COMMANDS.items():
            d = "n/a" if p is None else json.dumps(p)
            print(f"  {c:<24} {d}")
            if risk:
                print(f"  {'':<24} ! {risk}")
        return 0

    if args.command not in COMMANDS:
        print(f"unknown command {args.command!r}; use --list", file=sys.stderr)
        return 2

    default_params, risk = COMMANDS[args.command]
    if args.set:
        params = {}
        for item in args.set:
            if "=" not in item:
                print(f"--set expects KEY=VALUE, got {item!r}", file=sys.stderr)
                return 2
            k, v = item.split("=", 1)
            try:
                params[k.strip()] = int(v)
            except ValueError:
                try:
                    params[k.strip()] = float(v)
                except ValueError:
                    params[k.strip()] = v
    elif args.params:
        try:
            params = json.loads(args.params)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"--params must be valid JSON: {e}", file=sys.stderr)
            return 2
    else:
        if default_params is None:
            print(f"{args.command} has no safe default; pass --params explicitly",
                  file=sys.stderr)
            return 2
        params = default_params

    if risk:
        print(f"!! {args.command}: {risk}\n")

    email = args.email or input("Culligan account email: ").strip()
    password = getpass.getpass("Culligan password (not echoed, not stored): ")
    st, body = call("POST", "/api/v1/auth/login",
                    {"email": email, "password": password, "appId": APP_ID})
    del password
    if st != 200 or not body.get("success"):
        print(f"login failed: HTTP {st} {body}", file=sys.stderr)
        return 1
    token = body["data"]["accessToken"]
    print("authenticated")

    serial = args.serial
    if not serial:
        st, body = call("GET", "/api/v1/device/registry", token=token)
        devs = body.get("data", {}).get("devices", []) if st == 200 else []
        if len(devs) != 1:
            print("pass --serial (0 or multiple devices found)", file=sys.stderr)
            return 2
        serial = devs[0]["serialNumber"]
        print(f"device: {serial}  {devs[0].get('name')}")

    payload = {
        "command": args.command,
        "params": params,
        "protocolVersion": 1,
        "requestId": f"CC-{datetime.datetime.now().isoformat()}-{uuid.uuid4().hex[:8]}",
        "serialNumber": serial,
    }
    print("\nwould POST /api/v1/device/command:")
    print(json.dumps(payload, indent=2))

    if not args.apply:
        print("\nDRY RUN -- nothing sent. Add --apply to send.")
        return 0

    st, body = call("POST", "/api/v1/device/command", payload, token=token)
    print(f"\nHTTP {st}  {json.dumps(body)[:300]}")
    print("\nNote: 200 only means the cloud accepted the request. It does not confirm")
    print("the device applied it -- verify via telemetry or the app.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
