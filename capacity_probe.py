#!/usr/bin/env python3
"""Read the capacity configuration off a Culligan GBX controller.

Answers one question: does the unit have any working capacity at all?

A unit that regenerates every night regardless of water use is either running a
timeclock override or is permanently "exhausted" so that demand initiation fires
nightly. Those are different faults with different fixes, and this tells them
apart -- `regen_interval_days_setting` is the override, and a persistently
negative `capacity_remaining_tank_1` is the exhaustion.

THE FIELD THAT MATTERS is `total_capacity_volume_tank_1`, the working volume in
gallons that the regeneration logic actually spends.

`total_capacity` is a NAMEPLATE RATING and is misleading here. On the unit under
test it reads 1000 while the working volume reads 0 -- and `filter_total_capacity`
reads 1000 as well, which is the tell that 1000 is a generic default rather than
a computed figure. A technician who checks only `total_capacity` will conclude
capacity is configured correctly and stop looking.

Confirmed on real hardware 2026-08-28, ten hours after a regeneration:

    total_capacity_volume_tank_1     0      <- working capacity, gallons
    total_capacity                1000      <- nameplate, not operative
    reserve_capacity_volume        500
    capacity_remaining_tank_1     -571
    total_water_usage_today_tank_1  73

    0 - 500 - 71 = -571     (71 of today's 73 gal fell after the 03:12 regen)

The model fits every reading taken: -500, -501, -503, -552, -571. Capacity is
zero, the meter is fine, and the arithmetic is fine.

Read-only. Sends no commands. The password is read with getpass, never echoed,
never written to disk. Telemetry comes from /device/data, which carries no
account or address data; the registry call is used only to learn the serial.

    python capacity_probe.py
    python capacity_probe.py --all      # dump every datapoint
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
import urllib.error
import urllib.request

BASE_URL = "https://uniapi.culliganiot.com"
# Constant the Android app sends with every login.
APP_ID = "OAhRjZjfBSwKLV8MTCjscAdoyJKzjxQW"
# The Android app's HTTP client, mirrored as the rest of this toolkit does.
UA = "okhttp/4.12.0"
TIMEOUT = 30

# Readings taken from the unit under test on 2026-08-10, for regression compare.
BASELINE = {"total_capacity": 1000, "reserve_capacity_volume": 500,
            "average_daily_use": 204}

# `total_capacity` is a NAMEPLATE rating, not the operative figure -- it reads
# 1000 on a unit whose working capacity is zero, and `filter_total_capacity`
# reads 1000 too, which is what gave it away. The value the regeneration logic
# actually spends is `total_capacity_volume_tank_1`, in gallons.
WORKING = "total_capacity_volume_tank_1"

# The fields the diagnosis turns on.
TRIAD = (WORKING, "total_capacity", "reserve_capacity_volume",
         "capacity_remaining_tank_1")

# Anything that might carry a second, separately-programmed capacity figure.
# The regen logic may not use `total_capacity` at all, so cast wide.
RELEVANT = re.compile(
    r"capac|reserve|hardness|resin|salt|regen|grain|tank|dose|override|cycle",
    re.IGNORECASE,
)


class ProbeError(Exception):
    """Anything that stops the probe completing."""


def _post(path: str, payload: dict, token: str | None = None) -> dict:
    return _call("POST", path, payload, token)


def _get(path: str, token: str) -> dict:
    return _call("GET", path, None, token)


def _call(method: str, path: str, payload: dict | None, token: str | None) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json")
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310
            return json.loads(resp.read())
    except urllib.error.HTTPError as err:
        detail = err.read().decode(errors="replace")[:300]
        if err.code in (400, 401, 403):
            raise ProbeError(f"rejected: HTTP {err.code} {detail}") from err
        raise ProbeError(f"{method} {path}: HTTP {err.code} {detail}") from err
    except urllib.error.URLError as err:
        raise ProbeError(f"{method} {path}: transport error: {err.reason}") from err


def login(email: str, password: str) -> str:
    body = _post("/api/v1/auth/login",
                 {"email": email, "password": password, "appId": APP_ID})
    if not body.get("success"):
        raise ProbeError(f"login failed: {body}")
    return body["data"]["accessToken"]


def first_serial(token: str) -> tuple[str, str]:
    """Serial and model only. The registry also carries the installation
    address, contact details and dealer account -- none of it is read here."""
    body = _get("/api/v1/device/registry", token)
    devices = body.get("data", {}).get("devices", [])
    if not devices:
        raise ProbeError("no devices on this account")
    return devices[0].get("serialNumber", ""), devices[0].get("model", "?")


def datapoints(token: str, serial: str) -> dict:
    body = _get(f"/api/v1/device/data?serialNumber={serial}", token)
    return body.get("data", {}).get("datapoints", {})


def _num(dp: dict, key: str) -> float | None:
    v = dp.get(key)
    if isinstance(v, bool) or v is None:
        return None
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def expected_capacity_gallons(dp: dict) -> tuple[float, float] | None:
    """Plausible range for the working capacity, from resin volume and hardness.

    Resin exchanges roughly 20k-30k grains per cubic foot depending on salt
    dose. Treated volume is that divided by hardness in grains per gallon.
    A range, not a number: the salt dose sets where in the band it lands.
    """
    resin = _num(dp, "resin_tank_size")
    hardness = _num(dp, "hardness_value")
    if not resin or not hardness or resin <= 0 or hardness <= 0:
        return None
    return (resin * 20000.0 / hardness, resin * 30000.0 / hardness)


def verdict(dp: dict) -> None:
    working = _num(dp, WORKING)
    nameplate = _num(dp, "total_capacity")
    reserve = _num(dp, "reserve_capacity_volume")
    remaining = _num(dp, "capacity_remaining_tank_1")
    used_today = _num(dp, "total_water_usage_today_tank_1")

    print("\n=== the fields that decide it ===")
    for key in TRIAD:
        was = BASELINE.get(key)
        now = dp.get(key, "<ABSENT>")
        mark = ""
        if was is not None and _num(dp, key) is not None:
            mark = "  (unchanged)" if _num(dp, key) == was else f"  <-- WAS {was} on 08-10"
        if key == WORKING:
            mark += "   <<< the operative figure"
        elif key == "total_capacity":
            mark += "   (nameplate rating, not operative)"
        print(f"  {key:<30} {now}{mark}")

    print("\n=== verdict ===")
    if working is None:
        print(f"  {WORKING} is ABSENT from telemetry.")
        print("  Cannot evaluate. Re-run with --all.")
        return

    if working > 0:
        print(f"  {WORKING} reads {working:g} gal -- capacity IS configured.")
        if reserve is not None:
            print(f"  Usable = {working:g} - {reserve:g} = {working - reserve:g} gal.")
        print("  -> The blank-capacity fault is NOT present. If the unit is")
        print("     still regenerating nightly, the cause is elsewhere.")
        return

    print(f"  {WORKING} reads 0 gal.")
    print("  -> CONFIRMED: the unit has NO working capacity. It is permanently")
    print("     exhausted, so demand initiation fires every single night.")

    if nameplate:
        print(f"\n  Note {nameplate:g} in `total_capacity` is a nameplate rating,")
        print("  not the operative value -- `filter_total_capacity` carries the")
        print("  same 1000. A tech reading only that field will wrongly conclude")
        print("  capacity is fine. Point them at the field named above.")

    # Verify the arithmetic model, which is what makes this a measurement
    # rather than an inference.
    if reserve is not None and remaining is not None and used_today is not None:
        predicted = working - reserve - used_today
        print(f"\n  Model check: capacity_remaining = {WORKING} - reserve - used")
        print(f"    predicted  {working:g} - {reserve:g} - {used_today:g}"
              f" = {predicted:g}")
        print(f"    actual     {remaining:g}")
        drift = abs(predicted - remaining)
        if drift <= 5:
            print(f"    agree within {drift:g} gal -- model confirmed.")
        else:
            print(f"    differ by {drift:g} gal. Usage before the regen completed")
            print("    is counted in `used today` but not against capacity, so a")
            print("    small gap is expected; a large one is not.")

    band = expected_capacity_gallons(dp)
    if band:
        lo, hi = band
        resin = _num(dp, "resin_tank_size")
        hardness = _num(dp, "hardness_value")
        print(f"\n  What it SHOULD be: {resin:g} cu ft resin at {hardness:g} gpg")
        print(f"  hardness gives roughly {lo:,.0f}-{hi:,.0f} gal per cycle.")
        if reserve:
            print(f"  Less the {reserve:g} gal reserve: {lo - reserve:,.0f}"
                  f"-{hi - reserve:,.0f} gal usable.")
        avg = _num(dp, "average_daily_use") or used_today
        if avg and avg > 0 and reserve is not None:
            print(f"  At {avg:g} gal/day that is a regeneration every"
                  f" {(lo - reserve) / avg:.0f}-{(hi - reserve) / avg:.0f} days,")
            print("  against the observed 1.")


def regen_mode(dp: dict) -> None:
    """Distinguish demand initiation from a timeclock override.

    These are different faults with different fixes, and the readings that tell
    them apart are easy to miss in a 182-field dump.
    """
    override = _num(dp, "regen_interval_days_setting")
    pending = _num(dp, "regen_tonight_pending")
    trigger = dp.get("last_regen_trigger_tank_1")
    when = _num(dp, "time_of_regen")

    print("\n=== regeneration mode ===")
    if override is not None:
        if override == 0:
            print("  regen_interval_days_setting = 0 -> NO calendar/day override.")
            print("  The nightly cycle is NOT a timeclock fallback.")
        else:
            print(f"  regen_interval_days_setting = {override:g} -> a day override")
            print(f"  IS set: it will regenerate every {override:g} day(s) regardless")
            print("  of water use. This alone can explain a fixed cadence.")
    if trigger is not None:
        print(f"  last_regen_trigger_tank_1 = {trigger}  "
              f"({'app-initiated' if trigger in (10, 11) else 'device-initiated'};"
              " 10=immediate, 11=scheduled, per the controlled test)")
    if pending:
        print("  regen_tonight_pending = 1 -> another regeneration is ALREADY")
        print("  queued for tonight.")
    if when is not None:
        hh, mm = divmod(int(when), 100)
        print(f"  time_of_regen = {when:g} -> cycles start at {hh:02d}:{mm:02d}.")


def show_related(dp: dict, show_all: bool) -> None:
    keys = sorted(dp) if show_all else sorted(k for k in dp if RELEVANT.search(k))
    heading = "every datapoint" if show_all else "capacity / regen related"
    print(f"\n=== {heading} ({len(keys)} of {len(dp)}) ===")
    for k in keys:
        print(f"  {k:<44} {dp[k]}")
    if not show_all:
        print("\n  (--all dumps the rest; a separately-programmed capacity field")
        print("   would show up there under a name we have not seen.)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--email")
    ap.add_argument("--all", action="store_true",
                    help="dump every datapoint, not just capacity-related ones")
    args = ap.parse_args()

    email = args.email or input("Culligan account email: ").strip()
    password = getpass.getpass("Culligan password (not echoed, not stored): ")

    try:
        print("\nlogging in...")
        token = login(email, password)
        serial, model = first_serial(token)
        print(f"  ok -- {model}, serial ...{serial[-6:]}")

        print("fetching telemetry...")
        dp = datapoints(token, serial)
        print(f"  {len(dp)} datapoints")
    except ProbeError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    verdict(dp)
    regen_mode(dp)
    show_related(dp, args.all)
    print("\nRead-only run complete. No commands were sent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
