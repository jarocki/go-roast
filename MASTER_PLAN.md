# Plan: Interactsh Domain Classification + Web Interface

## Original Intent

Add version/client classification (v1.0.1 vs v1.0.2+, CLI vs web), accept web-client domains that are currently silently rejected, decode v1.0.1 nonces for session analytics, and provide a web UI for analysts without CLI access. The user provided a detailed 12-step implementation plan covering zbase32 decoding, classification engine, extended validation, decoder updates, campaign analysis, CLI output, MCP tools, and a full embedded web interface.

## Status: In Progress

## Context

go-roast decodes Interactsh OAST domain metadata from CLI-generated domains, but has three gaps:

1. **No version/client classification** - Cannot distinguish v1.0.1 from v1.0.2+, nor CLI from web client origins.
2. **Web client domains silently rejected** - `IsValidPreamble()` only accepts `[0-9a-v]`, but web client generates `[a-z]`.
3. **No web UI** - Analysts without CLI access cannot use the tool.

## Steps

1. zbase32 decoder (`pkg/roast/zbase32.go`)
2. Classification engine (`pkg/roast/classify.go`)
3. Wire classification into types (`pkg/roast/types.go`)
4. Broaden extraction regex (`pkg/roast/extractor.go`)
5. Extended validation (`pkg/roast/validate.go`)
6. Update decoder (`pkg/roast/decoder.go`)
7. Update campaign analysis (`pkg/roast/analyze.go`)
8. Update existing tests
9. Update CLI output (`cmd/roast/main.go`)
10. MCP integration (`mcp/tools.go`, `mcp/server.go`)
11. Web interface (`web/`)
12. justfile updates
