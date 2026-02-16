# Plan: go-roast Feature Development

## Original Intent

Enhance go-roast with classification capabilities, web UI, and advanced forensic attribution analytics. Phase 1 adds client/version detection and web interface. Phase 2 adds passive timezone attribution from timestamp deltas. Phase 3 adds machine clustering, counter gap analysis, and PID lifecycle tracking. Phase 4 adds temporal pattern analysis, enrichment data model, and attribution profile synthesis.

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

## Phase 3: 2nd Order Analytics

Machine clustering, counter gap analysis, and PID lifecycle tracking. Groups decoded domains by machine_id for cross-campaign correlation, detects missing domains via counter sequence gaps, and tracks process lifecycles for behavioral profiling.

**Status:** completed

### Implementation Summary

- Machine ID clustering with cross-campaign correlation (`pkg/roast/cluster.go`)
- Counter gap analysis for missing domain detection (`pkg/roast/gaps.go`)
- PID lifecycle tracking for process restart detection (`pkg/roast/lifecycle.go`)
- CLI: `roast analyze --cluster` flag (default enabled)
- MCP: `oast_cluster_machines` tool
- Markdown report: Machine Clustering, PID Lifecycle Analysis, Counter Gap Analysis sections
- MarkdownOptions struct for toggling 2nd order analytics sections

### Decision Log

- **DEC-CLUSTER-001**: Machine ID Clustering
  - Status: accepted
  - Rationale: Group decoded domains by machine_id to reveal distinct hosts, activity timelines, velocity, and cross-campaign correlation.
  - Location: `pkg/roast/cluster.go`
- **DEC-GAPS-001**: Counter Gap Analysis
  - Status: accepted
  - Rationale: Sequential counter in OAST domains enables detection of missing/uncaptured domains via gap analysis. Gaps >100 flagged as suspicious.
  - Location: `pkg/roast/gaps.go`
- **DEC-LIFECYCLE-001**: PID Lifecycle Tracking
  - Status: accepted
  - Rationale: Process ID combined with machine_id and counter ranges reveals process restart patterns and session boundaries for behavioral profiling.
  - Location: `pkg/roast/lifecycle.go`

## Phase 4: 3rd Order Analytics

Temporal pattern analysis, MCP enrichment data model, and attribution profile synthesis. Detects automated vs manual behavior, defines enrichment schema for GreyNoise/JA4/KEV integration, and synthesizes all signals into forensic narratives.

**Status:** planned

### Key Deliverables

- `pkg/roast/temporal.go` — Temporal pattern analysis (automated detection, work-hours)
- `pkg/roast/enrich.go` — Enrichment data model (GreyNoise, JA4, KEV)
- `pkg/roast/attribution.go` — Attribution profile synthesis (forensic narratives)
- MCP: `oast_enrich_ip`, `oast_attribution_profile` tools

### Decision Log

_(pending implementation)_
