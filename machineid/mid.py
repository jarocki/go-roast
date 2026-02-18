#!/usr/bin/env python3
"""
mid.py — Calculate the XID Machine ID (MID) for this machine.

Determines the platform, reads the platform-specific machine identifier,
and computes the 3-byte MID using both MD5 (xid <=1.4.0) and SHA-256
(xid >=1.5.0). With no arguments, enumerates all possible MID values
across interactsh/xid versions.

@decision: Uses only Python3 stdlib (hashlib, subprocess, platform, socket).
Mirrors the exact logic from rs/xid's readMachineID() and hostid_*.go files
per platform. Computes both MD5 and SHA-256 variants so analysts can match
MIDs regardless of which interactsh version generated the domain.

Usage:
    python3 mid.py              # Show all MID values for this machine
    python3 mid.py --json       # JSON output
    python3 mid.py --raw        # Show raw platform machine ID before hashing
"""

import hashlib
import json
import os
import platform
import socket
import subprocess
import sys


def read_file(path):
    """Read a file and return its contents stripped, or None."""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except (OSError, IOError):
        return None


def get_machine_id_linux():
    """Linux: /etc/machine-id, fallback /sys/class/dmi/id/product_uuid."""
    mid = read_file("/etc/machine-id")
    if mid:
        return mid, "/etc/machine-id"
    mid = read_file("/sys/class/dmi/id/product_uuid")
    if mid:
        return mid, "/sys/class/dmi/id/product_uuid"
    return None, None


def get_machine_id_darwin():
    """macOS: kern.uuid via sysctl, fallback to ioreg IOPlatformUUID."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "kern.uuid"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip(), "sysctl kern.uuid"
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "IOPlatformUUID" in line:
                    uuid = line.split('"')[-2]
                    if uuid:
                        return uuid, "ioreg IOPlatformUUID"
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None, None


def get_machine_id_windows():
    """Windows: Registry MachineGuid."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"
        )
        value, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return value, r"HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid"
    except (ImportError, OSError):
        pass
    try:
        result = subprocess.run(
            ["reg", "query",
             r"HKLM\SOFTWARE\Microsoft\Cryptography",
             "/v", "MachineGuid"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "MachineGuid" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[-1], r"HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid"
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None, None


def get_machine_id_freebsd():
    """FreeBSD: kern.hostuuid via sysctl."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "kern.hostuuid"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip(), "sysctl kern.hostuuid"
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None, None


def get_platform_machine_id():
    """Read the platform-specific machine identifier. Returns (value, source)."""
    env_mid = os.environ.get("XID_MACHINE_ID")
    if env_mid:
        return env_mid, "XID_MACHINE_ID env var"

    system = platform.system().lower()

    if system == "linux":
        return get_machine_id_linux()
    elif system == "darwin":
        return get_machine_id_darwin()
    elif system == "windows":
        return get_machine_id_windows()
    elif system == "freebsd":
        return get_machine_id_freebsd()

    return None, None


def get_hostname_fallback():
    """Hostname fallback used when platform ID is unavailable."""
    try:
        return socket.gethostname(), "os.Hostname() fallback"
    except OSError:
        return None, None


def compute_mid_md5(raw_id):
    """Compute MID using MD5 (xid <=1.4.0). Returns 3 bytes."""
    return hashlib.md5(raw_id.encode("utf-8")).digest()[:3]


def compute_mid_sha256(raw_id):
    """Compute MID using SHA-256 (xid >=1.5.0). Returns 3 bytes."""
    return hashlib.sha256(raw_id.encode("utf-8")).digest()[:3]


def format_mid(mid_bytes):
    """Format 3-byte MID as xx:xx:xx."""
    return ":".join(f"{b:02x}" for b in mid_bytes)


def main():
    args = sys.argv[1:]
    json_output = "--json" in args
    show_raw = "--raw" in args

    system = platform.system()
    hostname = socket.gethostname()

    platform_id, platform_source = get_platform_machine_id()
    hostname_id, _ = get_hostname_fallback()

    if platform_id:
        active_id = platform_id
        active_source = platform_source
    elif hostname_id:
        active_id = hostname_id
        active_source = "os.Hostname() fallback"
    else:
        if json_output:
            print(json.dumps({"error": "Could not determine machine ID"}, indent=2))
        else:
            print("ERROR: Could not determine machine ID from any source.")
        sys.exit(1)

    mid_md5 = compute_mid_md5(active_id)
    mid_sha256 = compute_mid_sha256(active_id)

    hostname_mid_md5 = compute_mid_md5(hostname) if hostname else None
    hostname_mid_sha256 = compute_mid_sha256(hostname) if hostname else None

    versions = [
        {
            "xid": "v1.0.0 - v1.4.0",
            "hash": "MD5",
            "interactsh": "v1.0.0 - v1.1.2",
            "mid": format_mid(mid_md5),
        },
        {
            "xid": "v1.5.0 - v1.6.0",
            "hash": "SHA-256",
            "interactsh": "v1.1.3 - v1.3.0",
            "mid": format_mid(mid_sha256),
        },
    ]

    if json_output:
        output = {
            "platform": system,
            "hostname": hostname,
            "machine_id_source": active_source,
            "machine_id_value": active_id if show_raw else "(use --raw to show)",
            "versions": [
                {
                    "xid_versions": v["xid"],
                    "hash_algorithm": v["hash"],
                    "interactsh_versions": v["interactsh"],
                    "mid": v["mid"],
                }
                for v in versions
            ],
        }
        if hostname_id and active_source != "os.Hostname() fallback":
            output["hostname_fallback"] = {
                "hostname": hostname,
                "mid_md5": format_mid(hostname_mid_md5),
                "mid_sha256": format_mid(hostname_mid_sha256),
            }
        print(json.dumps(output, indent=2))
    else:
        print(f"Platform:    {system}")
        print(f"Hostname:    {hostname}")
        print(f"ID Source:   {active_source}")
        if show_raw:
            print(f"Raw Value:   {active_id}")
        print()
        print("MID by interactsh / xid version:")
        print("-" * 72)
        print(f"  {'Interactsh':<20} {'xid':<18} {'Hash':<8} {'MID'}")
        print("-" * 72)
        for v in versions:
            print(f"  {v['interactsh']:<20} {v['xid']:<18} {v['hash']:<8} {v['mid']}")
        print("-" * 72)

        if mid_md5 == mid_sha256:
            print("\n  Note: MD5 and SHA-256 produce the same first 3 bytes for")
            print("  this machine ID (coincidence -- the full hashes differ).")
        else:
            print(f"\n  The same machine produces DIFFERENT MIDs depending on")
            print(f"  the interactsh version. An upgrade from v1.1.2 to v1.1.3")
            print(f"  changes the MID from {format_mid(mid_md5)} to {format_mid(mid_sha256)}.")

        if hostname_id and active_source != "os.Hostname() fallback":
            print(f"\n  Hostname fallback (if platform ID unavailable):")
            print(f"    MD5:    {format_mid(hostname_mid_md5)}")
            print(f"    SHA256: {format_mid(hostname_mid_sha256)}")

        env_mid = os.environ.get("XID_MACHINE_ID")
        if env_mid:
            print(f"\n  XID_MACHINE_ID is set -- this overrides the platform ID")
            print(f"  (xid v1.6.0+ / interactsh v1.3.0+ only).")
        else:
            print(f"\n  Tip: Set XID_MACHINE_ID env var to override (xid v1.6.0+).")


if __name__ == "__main__":
    main()
