#!/usr/bin/env python3
"""Attempt to write the working capacity on a Culligan GBX controller.

⚠ UNVERIFIED COMMAND. Read this before running with --apply.

`property.set` is a real verb in the app's command vocabulary, but in the
decompiled app it is only ever invoked on `CulliganGbx2Device`, via
setBypassSchedule, and its property-name argument was not statically
resolvable. So on a GBX1 two things are unproven:

  1. whether the device accepts property.set at all, and
  2. whether the property namespace matches the telemetry datapoint names.

(2) is a reasonable inference -- the telemetry field is called
`total_capacity_volume_tank_1` and that is the obvious key -- but it is an
inference, not an observation. Everything else this tool does is designed so
that a wrong inference is cheap AND INTERPRETABLE.

INTERPRETABILITY IS THE POINT

Transport is mirrored on set_device_time.py, the one command in this toolkit
verified end to end on real hardware. Same User-Agent (`okhttp/4.12.0`, what
the Android app sends), same envelope, same requestId format. That matters more
here than it did there: if this write is refused, the refusal has to mean
"property.set is not supported", not "the server did not like our client". A
rejection is only useful evidence when the only unusual thing in the request is
the thing under test.

For the same reason HTTP errors are RETURNED AND PRINTED, not raised. The
response body on a rejection is the single most valuable output this tool can
produce -- it is what distinguishes an unsupported command from a wrong
property name -- so it must never be swallowed into an exception message.

WHAT THIS DOES TO KEEP IT CHEAP

  * Dry run by default. --apply is required to send anything.
  * Captures the FULL datapoint set to a timestamped JSON file BEFORE writing,
    so the diagnostic evidence survives regardless of outcome. That matters:
    the case for a dealer visit rests on this field reading 0, and a partial
    or misdirected write would otherwise destroy it.
  * Refuses to guess which device to write to if the account has more than one.
  * Reads the value back afterwards and reports which of three things happened:
    rejected outright, accepted-but-ignored, or actually applied.
  * Refuses values outside a plausible band for the configured resin volume
    and hardness, so a typo cannot ask for something absurd.

WHY 2000 GALLONS IS THE DEFAULT

  resin_tank_size 1 cu ft, hardness_value 10 gpg, manual_salt_dosage 61.
  Resin exchanges ~20k grains/cu ft at a low salt dose and ~30k at a high one.
  20000 / 10 gpg = 2000 gallons, the CONSERVATIVE end of the band.

  Erring low is deliberate. Too low over-regenerates: wasteful, which is the
  condition the unit is already in. Too high lets hard water break through,
  which is the failure you would actually notice and dislike. If 2000 proves
  too conservative once it is cycling correctly, raise it then.

IF IT DOES NOT TAKE, that is informative rather than a setback: it means the
capacity is derived (most likely from the Aqua-Sensor, whose four
aquasensor_z_* datapoints all read 0) rather than stored, and no cloud write
would ever have fixed it. Either way, take the before-file to the dealer.

    python set_capacity.py                     # dry run
    python set_capacity.py --apply             # send it
    python set_capacity.py --value 2400 --apply

Stdlib only.
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = "https://uniapi.culliganiot.com"
# The Android app's HTTP client. Mirrored so a rejection means the COMMAND was
# refused, not the client -- see "Interpretability is the point" above.
UA = "okhttp/4.12.0"
APP_ID = "OAhRjZjfBSwKLV8MTCjscAdoyJKzjxQW"

FIELD = "total_capacity_volume_tank_1"
DEFAULT_VALUE = 2000

# Grains exchanged per cubic foot of resin, low and high salt dose.
GRAINS_PER_CUFT = (20000.0, 30000.0)
# Allow a little slack either side of the computed band.
BAND_SLACK = 1.5

# The app polls telemetry every 10-20s, and a command only acknowledges cloud
# receipt, so give the device a real chance before reading back.
READBACK_DELAY = 25


def call(method, path, body=None, token=None, timeout=25):
    """Returns (status, parsed_body). Never raises on an HTTP error -- the
    error body is the evidence."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + path, data=data, headers=headers,
                                 method=method)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:  # noqa: S310
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            return e.code, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return e.code, {"raw": raw[:400].decode("utf-8", "replace")}
    except urllib.error.URLError as e:
        return 0, {"transport_error": str(e.reason)}


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


def datapoints(token, serial):
    st, body = call("GET", f"/api/v1/device/data?serialNumber={serial}",
                    token=token)
    if st != 200:
        return {}
    return body.get("data", {}).get("datapoints", {})


def make_request_id():
    # Naive local time on purpose: the app's requestId carries no UTC offset.
    ts = datetime.datetime.now().isoformat()  # noqa: DTZ005
    return f"CC-{ts}-{uuid.uuid4().hex[:8]}"


def _num(dp, key):
    v = dp.get(key)
    if isinstance(v, bool) or v is None:
        return None
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def plausible_band(dp):
    resin = _num(dp, "resin_tank_size")
    hardness = _num(dp, "hardness_value")
    if not resin or not hardness or resin <= 0 or hardness <= 0:
        return None
    lo = resin * GRAINS_PER_CUFT[0] / hardness
    hi = resin * GRAINS_PER_CUFT[1] / hardness
    return lo / BAND_SLACK, hi * BAND_SLACK


def save_before(dp, serial):
    """Preserve the evidence before touching anything.

    Datapoints only -- /device/data carries no account, address or dealer
    information, unlike the registry.
    """
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")  # noqa: DTZ005
    path = f"capacity-before-{stamp}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"captured": stamp, "serial_tail": serial[-6:],
                   "datapoints": dp}, fh, indent=2, sort_keys=True)
    return path


def main():  # noqa: PLR0911
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--email", help="Culligan account email (prompted if omitted)")
    ap.add_argument("--app-id", default=APP_ID,
                    help="appId sent at login (default: the Android app's)")
    ap.add_argument("--serial", help="device serial; auto-detected if you have one")
    ap.add_argument("--field", default=FIELD, help=f"property key (default {FIELD})")
    ap.add_argument("--value", type=int, default=DEFAULT_VALUE,
                    help=f"gallons per cycle (default {DEFAULT_VALUE})")
    ap.add_argument("--apply", action="store_true",
                    help="actually send it. Without this, dry run only.")
    args = ap.parse_args()

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

    print("\ncapturing current state...")
    before = datapoints(token, serial)
    if not before:
        print("could not read /device/data -- refusing to write blind",
              file=sys.stderr)
        return 1
    path = save_before(before, serial)
    print(f"  {len(before)} datapoints saved to {path}")
    print(f"  {args.field} = {before.get(args.field, '<ABSENT>')}")

    band = plausible_band(before)
    if band and not (band[0] <= args.value <= band[1]):
        print(f"\nREFUSED: {args.value} gal is outside the plausible band "
              f"{band[0]:,.0f}-{band[1]:,.0f} for this unit's configured resin "
              f"volume and hardness.", file=sys.stderr)
        print("Pass a value inside it, or correct resin_tank_size / "
              "hardness_value first.", file=sys.stderr)
        return 2

    payload = {
        "command": "property.set",
        "params": {args.field: args.value},
        "protocolVersion": 1,
        "requestId": make_request_id(),
        "serialNumber": serial,
    }
    print("\nwould POST /api/v1/device/command:")
    print(json.dumps(payload, indent=2))

    if not args.apply:
        print("\nDRY RUN -- nothing sent. Re-run with --apply to send it.")
        print("This command is UNVERIFIED on GBX1; see the module docstring.")
        return 0

    print("\nsending...")
    st, body = call("POST", "/api/v1/device/command", payload, token=token)
    print(f"  HTTP {st}  {json.dumps(body)[:400]}")

    if st != 200 or not body.get("success"):
        print("\nREJECTED. Nothing was changed on the device.")
        print("The response body above is the useful part: it distinguishes an")
        print("unsupported command from a wrong property name. Transport matched")
        print("the verified timeDate.set exactly, so this is the command being")
        print("refused, not the client.")
        return 1

    print(f"\n  cloud accepted, requestId="
          f"{body.get('data', {}).get('requestId')}")
    print("  (acceptance means QUEUED, not applied -- reading back)")
    time.sleep(READBACK_DELAY)

    after = datapoints(token, serial)
    now = _num(after, args.field)
    print(f"\n  {args.field}: {_num(before, args.field)} -> {now}")

    if now is not None and now == args.value:
        print("\n  APPLIED. The write took.")
        print("  Re-run capacity_probe.py to confirm capacity_remaining goes")
        print("  positive after the next regeneration. If it does, this is a new")
        print("  finding: property.set works on GBX1 and the property namespace")
        print("  matches the datapoint names. Worth documenting in the API doc,")
        print("  which currently records it as unresolved.")
        return 0

    print(f"\n  NOT APPLIED WITHIN {READBACK_DELAY}s. This is not yet a verdict.")
    print("  The device may apply it on its next check-in, and a capacity change")
    print("  may only become visible at the next regeneration, when the")
    print("  controller recomputes the reset value.")
    print("\n  The decisive reading is capacity_remaining_tank_1 AFTER the next")
    print("  regeneration: positive means the new capacity took, negative means")
    print("  the controller is still using its own figure. Check with:")
    print("      python diff_capture.py <the before-file above>")
    print("\n  If it is still negative then, the capacity is DERIVED rather than")
    print("  stored -- consistent with all four aquasensor_z_* datapoints reading")
    print("  0 -- and no cloud write could have fixed it.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
