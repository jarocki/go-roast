# MASTER_PLAN: machineid/mid.py utility script

## Original Intent

User request: "Write a multiplatform python3 script, mid.py, that determines the platform it is run on, and calculates the resultant MachineID. With no arguments, it should enumerate all of the possible values of MID given different versions of interactsh and xid. Check that python script into the machineid directory where the recently created README.md resides."

## Phase 1: mid.py

**Status:** completed

- Detect platform (Linux, macOS, Windows, FreeBSD)
- Read platform-specific machine identifier
- Compute MID with both MD5 (xid <=1.4.0) and SHA-256 (xid >=1.5.0)
- Show version-mapped output table
- Support --json and --raw flags

### Decision Log

#### DEC-MID-001: Python3 stdlib only
**Decision:** Use only Python3 standard library (hashlib, subprocess, platform, socket). No third-party dependencies.
**Rationale:** Script must run on any machine with Python3 installed — forensic analysts shouldn't need pip to calculate a MID.
**Outcome:** Implemented. All platform detection and hashing uses stdlib.

#### DEC-MID-002: Mirror xid's readMachineID() logic exactly
**Decision:** Match the exact platform-specific source order and fallback chain from rs/xid's hostid_*.go files.
**Rationale:** MID calculation must produce identical results to what interactsh actually generates, or the tool is useless for correlation.
**Outcome:** Implemented. Linux (/etc/machine-id, /sys/class/dmi/id/product_uuid), macOS (sysctl kern.uuid, ioreg), Windows (Registry MachineGuid), FreeBSD (sysctl kern.hostuuid), hostname fallback, XID_MACHINE_ID env override.
