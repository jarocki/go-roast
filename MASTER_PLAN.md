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

- **DEC-CLASSIFY-001**: zbase32 nonce decoding for v1.0.1 session tracking (implemented, not annotated in code)
- **DEC-CLASSIFY-002**: Multi-signal classification engine (implemented, not annotated in code)
- **DEC-CLASSIFY-003**: Cross-reference validation (implemented, not annotated in code)

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

**Status:** completed

### Implementation Summary

- Temporal pattern analysis (`pkg/roast/temporal.go`): mean/stddev intervals, burst detection (<5s), quiet period detection (>1hr), automated likelihood scoring, active hours/days analysis, reasoning explanations
- Enrichment data model (`pkg/roast/enrich.go`): GreyNoise (noise/RIOT/classification), JA4 fingerprints, KEV (CVE/vendor/product), source IP, ASN, tags
- Attribution profile synthesis (`pkg/roast/attribution.go`): confidence scoring (low/medium/high), forensic narrative generation combining all signals (timezone, temporal, clusters, PIDs, gaps, enrichment)
- MCP: `oast_attribution_profile` (batch forensic profiles), `oast_enrich_ip` (per-domain enrichment)
- Markdown report: Temporal Analysis and Attribution Profiles sections in campaign reports
- Tests: temporal (8 cases), enrich (6 cases), attribution (4+ cases)
- CampaignAnalysis: wired 3rd order analytics into existing pipeline

### Decision Log

- **DEC-TEMPORAL-001**: Temporal Pattern Analysis
  - Status: accepted
  - Rationale: Inter-domain timing analysis reveals automated vs manual behavior. Regular intervals with low stddev indicate scripted scanning; irregular intervals spanning hours suggest manual testing; periodic bursts with quiet periods suggest scheduled jobs.
  - Location: `pkg/roast/temporal.go`
- **DEC-ENRICH-001**: Enrichment Data Model
  - Status: accepted
  - Rationale: Schema for external enrichment (GreyNoise, JA4, KEV) attached to DecodedOAST. This is the data model only; actual API calls happen via MCP tool composition.
  - Location: `pkg/roast/enrich.go`
- **DEC-ATTRIBUTION-001**: Attribution Profile Synthesis
  - Status: accepted
  - Rationale: Combines all forensic signals (timezone, temporal, clusters, PIDs, gaps, enrichment) into a human-readable narrative and confidence score for attribution.
  - Location: `pkg/roast/attribution.go`
