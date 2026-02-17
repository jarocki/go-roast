# Plan: Roast v2 Presentation Layer Completeness

## Original Intent

Ensure all v2 forensic analytics (timezone, clustering, gaps, lifecycles, temporal, attribution) are fully reachable from every output surface: web UI, CLI (JSON/CSV/table/markdown), and MCP tools. Backend computation is complete — this plan closes the presentation gaps.

## Phase 1: Web UI Analytics Panels

Render all v2 analytics in the web frontend analyze results. Currently the backend returns full data but app.js only displays basic metrics and consensus timezone.

**Status:** completed

### Key Deliverables

- Machine Clustering panel in analyze results (campaigns, PIDs, duration, velocity)
- Counter Gap Analysis table
- PID Lifecycle table
- Temporal Analysis panel (mean interval, bursts, automated likelihood, active hours)
- Attribution Profiles panel with narrative text
- Enhanced CSV export including all analytics fields

### Decision Log

No formal DEC-IDs required — web UI rendering follows existing patterns in app.js. Enhanced CSV export mirrors CLI CSV structure (24-column flattened machine-cluster rows).

## Phase 2: CLI Output Format Completeness

Add CSV and table output formats for the analyze command. Currently only JSON and markdown are supported.

**Status:** completed

### Key Deliverables

- CSV output for `roast analyze` (machine clusters, temporal profiles, attribution as flattened rows)
- Table output for `roast analyze` (summary view with key metrics)
- Ensure `--output csv` and `--output table` work for analyze command

### Decision Log

- **DEC-CLI-CSV-001**: Analyze CSV Output — Machine-Cluster Rows. One row per machine cluster with all 2nd/3rd order analytics flattened into 24 columns for spreadsheet/DuckDB consumption.
- **DEC-CLI-TABLE-001**: Analyze Table Output — Machine Summary Table. Compact terminal table with key forensic signals (machine, domains, campaigns, timezone, automated likelihood, confidence) for operator quick overview.
