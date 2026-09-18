#!/usr/bin/env python3
"""Read or test a Tapo device locally with python-kasa; never save credentials."""

import argparse
import asyncio
import getpass
import logging

from kasa import Credentials, Device, DeviceConfig
from kasa.deviceconfig import DeviceConnectionParameters


async def verify_power(device, expected):
    for attempt in range(5):
        await device.update()
        if device.is_on == expected:
            return
        if attempt < 4:
            await asyncio.sleep(0.5)
    raise RuntimeError("Device did not report the requested power state")


async def run(args, password):
    config = DeviceConfig(
        host=args.host,
        timeout=5,
        credentials=Credentials(args.username, password),
        connection_type=DeviceConnectionParameters.from_values(
            "SMART.TAPOSWITCH", "KLAP", login_version=2, http_port=80
        ),
    )
    device = None
    try:
        device = await Device.connect(config=config)
        original = device.is_on
        print(f"Connected: {device.model}; name: {device.alias}", flush=True)
        print(f"Original power: {'on' if original else 'off'}", flush=True)
        if not args.test_toggle:
            return
        try:
            if original:
                await device.turn_off()
            else:
                await device.turn_on()
            await verify_power(device, not original)
            print(f"Verified power: {'off' if original else 'on'}", flush=True)
            await asyncio.sleep(1)
        finally:
            # Restore even if the initial command succeeds but its response is lost.
            if original:
                await device.turn_on()
            else:
                await device.turn_off()
            await verify_power(device, original)
            print(f"Restored and verified power: {'on' if original else 'off'}", flush=True)
    finally:
        if device is not None:
            await device.disconnect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--test-toggle", action="store_true",
                        help="Briefly toggle power, verify, then restore it")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    password = getpass.getpass("Tapo password (not saved): ")
    try:
        asyncio.run(run(args, password))
    except Exception as exc:
        print(f"Control failed: {type(exc).__name__}: {exc}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
