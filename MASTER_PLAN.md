# Plan: go-roast Feature Development

## Original Intent

Enhance go-roast with classification capabilities, web UI, and timezone-based attribution. Phase 1 adds client/version detection and web interface. Phase 2 adds passive timezone attribution from timestamp deltas.

## Phase 1: Classification + Web Interface

Add version/client classification (v1.0.1 vs v1.0.2+, CLI vs web), accept web-client domains that are currently silently rejected, decode v1.0.1 nonces for session analytics, and provide a web UI for analysts without CLI access.

**Status:** completed

### Implementation Summary

- zbase32 decoder for v1.0.1 nonces
- Classification engine (CLI/web, v1.0.1/v1.0.2+)
- Extended validation for web client domains
- Full web UI with CSV upload
- Cross-reference validation
- Enhanced markdown reports

### Decision Log

- **DEC-CLASSIFY-001**: zbase32 nonce decoding for v1.0.1 session tracking
- **DEC-CLASSIFY-002**: Multi-signal classification engine (nonce format, timestamp analysis, pattern matching)
- **DEC-CLASSIFY-003**: Cross-reference validation for campaign attribution confidence

## Phase 2: Timezone Estimation

Add passive timezone attribution by comparing XID timestamps (client local time) against DNS/web log timestamps (UTC). The delta reveals the client's timezone offset as a forensic signal.

**Status:** completed

### Implementation Summary

- Core timezone estimation engine (`pkg/roast/timezone.go`): EstimateTimezone, EstimateTimezoneFromNonce, ConsensusTimezone, QuantizeOffset
- Standard UTC offset quantization including half-hour (:30) and 45-minute (:45) zones
- Confidence levels: low (single domain), medium (2-5 agree), high (6+ agree or multi-method agreement)
- XID + nonce cross-check: when both timestamps agree, confidence is bumped
- Decoder integration: DecodeWithLogTime, DecodeBatchWithLogTimes
- Analyzer integration: AnalyzeCampaignWithTimestamps with consensus computation
- Markdown reports: timezone analysis section with consensus and per-offset table
- CLI: `roast decode --log-time` and `roast analyze --timestamps` (CSV/TSV input)
- MCP: `oast_estimate_timezone` tool
- Web UI: optional log timestamp input, timezone estimate display in decode/analyze results
- Tests: 6 test suites covering standard offsets, half-hour zones, Nepal/Chatham, clock skew, quantization, and consensus algorithms

### Decision Log

- **DEC-TIMEZONE-001**: Timezone Offset Estimation from Timestamp Deltas
  - Status: accepted
  - Rationale: XID timestamps encode client local time, DNS logs are UTC. The delta reveals timezone offset as a passive attribution signal.
  - Location: `pkg/roast/timezone.go`
