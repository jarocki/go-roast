# XID Machine ID (MID) — Deep Dive

How Interactsh generates the 3-byte Machine ID embedded in every OAST domain,
traced across every version of both `rs/xid` and `projectdiscovery/interactsh`.

---

## 1. XID Byte Layout

Every Interactsh correlation ID (CID) is a 12-byte XID encoded in base32hex (20 characters):

```
 0         1         2         3         4         5         6         7         8         9        10        11
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
| Timestamp (4 bytes, seconds)      | Machine ID (3 bytes) | PID (2 bytes)  | Counter (3 bytes)    |
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
```

| Field       | Bytes | Offset | Description                              |
|-------------|-------|--------|------------------------------------------|
| Timestamp   | 4     | 0      | Unix seconds — client's **local clock**  |
| Machine ID  | 3     | 4      | First 3 bytes of hash(platform machine ID) |
| PID         | 2     | 7      | `os.Getpid() % 65536`                   |
| Counter     | 3     | 9      | Atomically incremented from random seed  |

The timestamp encodes the client's **local wall clock**, not UTC. This is the basis
for the timezone estimation technique described in [John Jarocki's LABScon 2024 research](https://github.com/topics/snl-cyber-sec).

---

## 2. How Machine ID Is Calculated

The MID is generated once per process at init time by `readMachineID()` in `rs/xid`.
The algorithm is:

```
1. Read a platform-specific machine identifier (see table below)
2. Hash it (MD5 in xid <=1.4.0, SHA-256 in xid >=1.5.0)
3. Take the first 3 bytes of the hash digest
```

If the platform identifier cannot be read, the fallback chain is:
1. `os.Hostname()` → hash → first 3 bytes
2. Random 3 bytes (panics if crypto/rand also fails)

Since xid v1.6.0 (May 2025), the `XID_MACHINE_ID` environment variable can
override the platform identifier entirely.

### Platform-Specific Sources

| Platform | Source                                           | Example Value                                  |
|----------|--------------------------------------------------|------------------------------------------------|
| Linux    | `/etc/machine-id`                                | `0a0d7ae24460406eaf253dfd08dbe175`              |
| Linux    | `/sys/class/dmi/id/product_uuid` (fallback)      | `564d8b78-5064-9467-ac11-4ba9272a7cd9`          |
| macOS    | `sysctl kern.uuid` (via syscall)                 | `70855F70-9BF7-3D6D-991D-D475B75E7CAB`          |
| Windows  | Registry `HKLM\SOFTWARE\Microsoft\Cryptography`  → `MachineGuid` | `5eba70ca-ad57-4598-807e-8ff7d4910da8` |
| FreeBSD  | `sysctl kern.hostuuid`                           | `123e4567-e89b-12d3-a456-426614174000`          |
| Fallback | `os.Hostname()`                                  | `operator-workstation`                          |

**Key forensic insight**: The same physical machine always produces the same MID
(unless the machine-id file changes, e.g., after OS reinstall). Different machines
produce different MIDs. This enables cross-campaign correlation — the same MID
appearing in different OAST campaigns implies the same operator machine.

---

## 3. Hash Evolution: MD5 to SHA-256

The hash algorithm changed in a single commit. Here is the exact timeline:

### xid Version History

| xid Version | Release Date    | Hash Algorithm | Key Change                                      |
|-------------|-----------------|----------------|-------------------------------------------------|
| v1.0.0      | 2015-07-13      | MD5            | Initial release                                 |
| v1.1.0      | 2017-09-13      | MD5            | Added `NilID()`, `Bytes()` methods              |
| v1.2.0      | 2018-05-31      | MD5            | Added encoding interfaces                       |
| v1.2.1      | 2018-06-02      | MD5            | Bug fix release                                 |
| v1.3.0      | 2021-02-22      | MD5            | Added `IsNil()`, `IsZero()`                     |
| v1.3.1      | 2021-03-15      | MD5            | Maintenance release                             |
| v1.4.0      | 2022-09-07      | MD5            | Added `Sort()`, performance improvements        |
| **v1.5.0**  | **2023-04-25**  | **SHA-256**    | **MD5 → SHA-256 transition** (commit `e33d3ea`) |
| v1.6.0      | 2025-05-19      | SHA-256        | Added `XID_MACHINE_ID` env var override         |

The critical transition is **xid v1.5.0** (April 25, 2023):

```go
// Before v1.5.0 (MD5):
import "crypto/md5"
hw := md5.New()
hw.Write(id)
copy(machineID[:], hw.Sum(nil))

// v1.5.0+ (SHA-256):
import "crypto/sha256"
hw := sha256.New()
hw.Write(id)
copy(machineID[:], hw.Sum(nil))
```

**Forensic implication**: The same physical machine produces **different MIDs**
depending on which xid version was used. An operator upgrading interactsh from
v1.1.2 → v1.1.3 would appear as a "new" machine even though the hardware is
identical.

### Interactsh → xid Dependency Map

| Interactsh Version | Release Date   | xid Dependency | Hash Algorithm | Notes                                |
|--------------------|----------------|----------------|----------------|--------------------------------------|
| v1.0.0             | 2021-07-14     | xid v1.3.0     | MD5            | Initial public release               |
| v1.0.1             | 2021-10-05     | xid v1.3.0     | MD5            | Nonce contains timestamp+counter (yyy pattern) |
| v1.0.2             | 2022-03-20     | xid v1.3.0     | MD5            | Nonce switched to crypto/rand        |
| v1.0.3             | 2022-06-01     | xid v1.4.0     | MD5            | —                                    |
| v1.0.4 – v1.0.7   | 2022           | xid v1.4.0     | MD5            | Various feature releases             |
| v1.1.0 – v1.1.2   | 2023-01 – 2023-03 | xid v1.4.0  | MD5            | Last MD5-based interactsh versions   |
| **v1.1.3**         | **2023-05-01** | **xid v1.5.0** | **SHA-256**    | **First SHA-256 interactsh version** |
| v1.1.4 – v1.1.9   | 2023           | xid v1.5.0     | SHA-256        | —                                    |
| v1.2.0 – v1.2.4   | 2024           | xid v1.5.0     | SHA-256        | —                                    |
| v1.3.0             | 2025           | xid v1.6.0     | SHA-256        | Latest; adds `XID_MACHINE_ID` support|

**Version detection shortcut**: If the OAST nonce contains trailing `yyy` characters
(z-base-32 encoded zeros), the domain was generated by interactsh **v1.0.1 or earlier**,
which used `xid v1.3.0` with **MD5** hashing.

---

## 4. Nonce Encoding and Version Fingerprinting

The nonce (everything after the 20-char preamble) reveals the interactsh version:

| Interactsh Version | Nonce Content                     | Encoding  | Detection Signal               |
|--------------------|-----------------------------------|-----------|---------------------------------|
| v1.0.1 (CLI)       | Timestamp (4B) + Counter (4B)     | z-base-32 | Trailing `yyy` chars (counter starts at 0) |
| v1.0.2+ (CLI)      | `crypto/rand` random bytes        | z-base-32 | High entropy, no `yyy` pattern  |
| Web client (old)   | Timestamp (4B) + Counter (4B)     | z-base-32 | Preamble uses `[a-z]` not base32hex |
| Web client (new)   | `crypto/rand` random bytes        | z-base-32 | Preamble uses `[a-z]` not base32hex |

The z-base-32 alphabet is: `ybndrfg8ejkmcpqxot1uwisza345h769`

Note that `y` maps to `0` in z-base-32, which is why zero-padded counters produce
runs of `y` characters.

---

## 5. Comparison with LABScon 2024 Presentation

The presentation "Tracking the Cyberspace Ghost from OAST to OAST" (LABScon 2024)
established the foundational research for OAST domain forensics. Below is a
comparison of presentation claims against verified source code findings.

### Confirmed Correct

| Slide | Claim | Verification |
|-------|-------|--------------|
| 17 | XID is a "K-sortable unique identifier" with 12-byte structure | Confirmed: `id.go` defines `type ID [rawLen]byte` where `rawLen = 12` |
| 17 | Preamble encoded in base32hex, nonce in z-base-32 | Confirmed: preamble uses `0123456789abcdefghijklmnopqrstuv`, nonce uses `ybndrfg8ejkmcpqxot1uwisza345h769` |
| 19 | Byte layout: TS(4) + MID(3) + PID(2) + Counter(3) | Confirmed: matches `id.go` field offsets exactly |
| 21 | MID uses SHA-256 of platform machine ID | Confirmed for xid v1.5.0+ (current versions) |
| 21 | Platform sources: Linux `/etc/machine-id`, macOS `sysctl kern.uuid`, Windows Registry `MachineGuid`, FreeBSD `sysctl kern.hostuuid` | Confirmed: matches `hostid_*.go` platform files |
| 21 | Fallback to hostname or random bytes | Confirmed: `readMachineID()` fallback chain |
| 22 | z-base-32 `y` = 0, producing `yyy` runs in v1.0.1 nonces | Confirmed: z-base-32 alphabet starts with `y` mapping to 0 |
| 22 | v1.0.2 (2022-03-20) fixed the nonce to use random bytes | Confirmed: commit `0166128` switched to `crypto/rand` |
| 22 | Web client uses z-base-32 for both preamble and nonce | Confirmed: web client JavaScript uses z-base-32 throughout |
| 37 | "The timestamp is relative to the timezone setting of the interactsh client" | Confirmed: XID encodes `time.Now().Unix()` which uses the client's local wall clock, not UTC |

### Missing from Presentation

The following details are absent from the presentation but are important for
forensic analysis:

| Topic | What's Missing | Why It Matters |
|-------|---------------|----------------|
| **Hash evolution** | Presentation shows SHA-256 (slide 21) but does not mention that older versions used MD5, or when the transition occurred | An analyst comparing MIDs across pre/post April 2023 domains would see different MIDs for the same machine and might incorrectly conclude they're different operators |
| **Exact xid version mapping** | No mapping of interactsh versions to xid versions | Without this, analysts can't determine which hash algorithm produced a given MID |
| **`XID_MACHINE_ID` env var** | Not mentioned (added May 2025, after the presentation) | Operators can now spoof their MID by setting this environment variable, undermining machine correlation |
| **Linux fallback path** | `/sys/class/dmi/id/product_uuid` as secondary source on Linux | In containerized environments where `/etc/machine-id` may be absent, the DMI UUID is used instead |
| **Automated timezone estimation at scale** | Presentation demonstrates the differential technique (GA cookie vs XID timestamp, slide 36) and notes timestamps are local (slide 37), but doesn't formalize it as a systematic pipeline for bulk timezone estimation across campaigns | Roast's `EstimateTimezone()` and `ConsensusTimezone()` automate this across many domains with confidence scoring |
| **Counter initialization** | Counter is seeded from `crypto/rand`, not started at 0 | Important for counter gap analysis — the first domain from a process won't have counter=0 (unlike v1.0.1 nonces) |
| **PID truncation** | PID is stored as `os.Getpid() % 65536` (2 bytes) | On Linux with high PIDs (>65535), different processes can produce the same PID field |

### Potentially Misleading

| Slide | Claim | Issue |
|-------|-------|-------|
| 19 | "Preamble: Calculated from machine data" | Vague — the preamble contains the full XID (timestamp + MID + PID + counter), not just machine data. The MID specifically is derived from machine data. |

### Presentation Discoveries Not in Source Code

The presentation contains several original forensic findings that go beyond what
source code analysis alone reveals:

- **APT28/MASEPIE/STEELHOOK case study** (slides 24-35): Demonstrated that threat
  actors recycle OAST domains from interactsh documentation, and that domains with
  the `2vtc` campaign ID span from Feb 2023 to Aug 2024, all using interactsh v1.0.1
  (pre-crypto/rand nonces). The presentation identified 189 pDNS lookups sharing
  the same campaign.

- **Custom alphabet detection** (slides 27-28): Some MASEPIE domains don't match
  any known base32 variant, suggesting APT28 used modified or custom tooling.

- **Differential time analysis** (slides 36-37): Demonstrated the core technique —
  comparing an external timestamp (GA cookie) against the XID-encoded timestamp to
  corroborate the decode and reveal timezone context. Combined with the explicit
  note that "the timestamp is relative to the timezone setting of the interactsh
  client," this establishes the foundation for timezone estimation.

---

## 6. Roast Implementation

Roast decodes the MID from bytes 4-6 of the XID and formats it as `xx:xx:xx`:

```go
// pkg/roast/decoder.go
result.MachineID = fmt.Sprintf("%02x:%02x:%02x", bytes[4], bytes[5], bytes[6])
```

Roast does **not** attempt to reverse the MID hash back to a hostname or machine-id,
as the 3-byte truncation makes this computationally infeasible. Instead, MID is used
as an opaque fingerprint for:

- **Machine clustering** (`pkg/roast/cluster.go`): Grouping domains by MID across campaigns
- **PID lifecycle tracking** (`pkg/roast/lifecycle.go`): Tracking process restarts on the same machine
- **Counter gap analysis** (`pkg/roast/gaps.go`): Detecting unobserved domains per (MID, PID) pair
- **Attribution profiles** (`pkg/roast/attribution.go`): Synthesizing all signals per machine

---

## 7. Forensic Considerations

### Same MID, Different Machine?

The 3-byte MID provides only 2^24 (16.7 million) possible values. Birthday paradox
suggests collisions become likely around ~4,000 machines. In targeted analysis of
small campaigns this is negligible; in large-scale passive DNS datasets, MID
collisions are possible.

### MID Changes on the Same Machine

The MID will change if:
- The machine-id file is regenerated (e.g., OS reinstall, VM clone)
- The xid library is upgraded across the MD5 → SHA-256 boundary
- The `XID_MACHINE_ID` environment variable is set (xid v1.6.0+)
- The hostname changes (if using hostname fallback)

### Container and VM Considerations

- Docker containers may share the host's `/etc/machine-id` or have their own
- VMs cloned from a template may initially share the same machine-id
- Cloud instances typically get unique machine-ids at provisioning time
- Kubernetes pods running interactsh as a sidecar will share the node's MID

### Detecting the Hash Algorithm

Given an OAST domain, determine which hash was used:

1. Check for trailing `yyy` in nonce → **interactsh v1.0.1** → **xid v1.3.0** → **MD5**
2. Check the XID timestamp: if before May 2023 → likely **MD5** (interactsh v1.1.2 or earlier)
3. If timestamp is after May 2023 → likely **SHA-256** (interactsh v1.1.3+)
4. The transition window (April-May 2023) is ambiguous — could be either

---

## References

- [rs/xid](https://github.com/rs/xid) — XID library source code
- [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) — Interactsh source code
- [xid v1.5.0 release](https://github.com/rs/xid/releases/tag/v1.5.0) — MD5 → SHA-256 commit
- [interactsh commit 0166128](https://github.com/projectdiscovery/interactsh/commit/0166128e3a382c6b08b002e2d4343fa8a9a48a96) — v1.0.2 nonce randomization
- [z-base-32 paper](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) — Zooko O'Wheilacronx's encoding spec
- LABScon 2024: "Tracking the Cyberspace Ghost from OAST to OAST" — John Jarocki
