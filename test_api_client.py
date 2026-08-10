#!/usr/bin/env python3
"""
Exercise the CulliganApiClient against the live API. Read-only by default.

Password is read with getpass -- never echoed, never stored, never logged.

    python test_api_client.py                 # reads only
    python test_api_client.py --write-test    # also flips away mode on and off
"""

import argparse
import asyncio
import getpass
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "custom_components", "culligan_azure"))

import aiohttp  # noqa: E402
from api import CulliganApiClient, CulliganAuthError, CulliganError  # noqa: E402

INTERESTING = [
    "current_flow_rate", "total_water_usage_today_tank_1",
    "total_water_usage_since_install_tank_1", "average_daily_use",
    "capacity_remaining_tank_1", "days_salt_remaining",
    "manual_salt_level_rem_calc", "hardness_value", "time_rem_in_position",
    "away_mode", "regen_tonight_pending", "days_since_last_regen_tank_1",
    "total_regens_since_install", "total_regens_last_14_days",
    "last_regen_date_time_tank_1", "next_regen_date_time",
    "last_power_up_time", "rssi", "days_in_error", "system_error_bit_flags",
    "gbx_firmware_version", "wifi_module_fw_version",
]


async def run(email: str, password: str, write_test: bool) -> int:
    async with aiohttp.ClientSession() as session:
        client = CulliganApiClient(session, email, password)

        print("logging in...")
        try:
            await client.async_login()
        except CulliganAuthError as e:
            print(f"  AUTH FAILED: {e}", file=sys.stderr)
            return 1
        print("  ok")

        print("\nfetching device registry...")
        devices = await client.async_get_devices()
        if not devices:
            print("  no devices", file=sys.stderr)
            return 1
        for d in devices:
            print(f"  {d.get('serialNumber')}  {d.get('name')!r}  "
                  f"model={d.get('model')}  online={d.get('status',{}).get('connection',{}).get('online')}")
        serial = devices[0]["serialNumber"]

        print("\nfetching state...")
        state = await client.async_get_state(serial)
        print(f"  connected={state.get('connected')}  "
              f"errors={state.get('errors')}  alerts={state.get('alerts')}")

        print("\nfetching telemetry...")
        dp = await client.async_get_datapoints(serial)
        print(f"  {len(dp)} datapoints")
        for k in INTERESTING:
            if k in dp:
                print(f"    {k:<40} {dp[k]}")

        # Registry should already carry the same properties -- confirm, because
        # if true an integration needs only ONE call per poll instead of three.
        props = devices[0].get("properties") or {}
        print(f"\nregistry embedded properties: {len(props)} "
              f"({'matches telemetry' if len(props) == len(dp) else 'DIFFERS from telemetry'})")

        if not write_test:
            print("\nread-only run complete. Pass --write-test to exercise a command.")
            return 0

        print("\n--- write test: away mode on, then off ---")
        before = (await client.async_get_datapoints(serial)).get("away_mode")
        print(f"  away_mode before: {before}")
        rid = await client.async_set_away_mode(serial, True)
        print(f"  sent awayMode.set active=1, requestId={rid}")
        await asyncio.sleep(12)
        mid = (await client.async_get_datapoints(serial)).get("away_mode")
        print(f"  away_mode after on: {mid}")
        rid = await client.async_set_away_mode(serial, False)
        print(f"  sent awayMode.set active=0, requestId={rid}")
        await asyncio.sleep(12)
        after = (await client.async_get_datapoints(serial)).get("away_mode")
        print(f"  away_mode after off: {after}")
        if mid != before:
            print("\n  WRITE PATH CONFIRMED -- the datapoint tracked the command.")
        else:
            print("\n  away_mode did not visibly change; the device may lag, or this")
            print("  datapoint may not reflect the command. Re-check in the app.")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--email")
    ap.add_argument("--write-test", action="store_true")
    args = ap.parse_args()
    email = args.email or input("Culligan account email: ").strip()
    password = getpass.getpass("Culligan password (not echoed, not stored): ")
    try:
        return asyncio.run(run(email, password, args.write_test))
    except CulliganError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
