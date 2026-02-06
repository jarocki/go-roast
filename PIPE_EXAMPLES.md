# roast pipe - DuckDB Integration Examples

The `roast pipe` command processes input line-by-line, extracting and decoding OAST domains into NDJSON format optimized for DuckDB analysis.

## Basic Usage

```bash
# Process a log file
roast pipe -f access.log > oast-data.ndjson

# Process from stdin
cat application.log | roast pipe > oast-data.ndjson

# Skip lines without OAST domains
roast pipe -f scan-results.txt --skip-empty > oast-data.ndjson

# Quiet mode (no stderr summary)
roast pipe -f logs.txt --quiet > oast-data.ndjson
```

## Output Format

Each line is a JSON object:

```json
{
  "line_num": 2,
  "line": "2024-01-15 10:24:12 WARN: Suspicious DNS query: c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro",
  "oast_count": 1,
  "oast_decoded": [
    {
      "original": "c58bduhe008dovpvhvugcfemp9yyyyyyn",
      "timestamp": "2021-09-26T14:07:54-04:00",
      "machine_id": "2e:00:10",
      "pid": 56447,
      "counter": 4165629,
      "nonce": "cfemp9yyyyyyn",
      "ksort": "c58bdu",
      "campaign": "he008",
      "valid": true
    }
  ]
}
```

## DuckDB Analysis Examples

### 1. Load and inspect data

```sql
-- View all records
SELECT * FROM read_json('oast-data.ndjson');

-- Summary statistics
SELECT
    COUNT(*) as total_lines,
    SUM(oast_count) as total_oasts,
    COUNT(CASE WHEN oast_count > 0 THEN 1 END) as lines_with_oasts
FROM read_json('oast-data.ndjson');
```

### 2. Unnest and extract OAST fields

```sql
-- Get all decoded OAST domains with their metadata
SELECT
    line_num,
    unnest(oast_decoded).original as subdomain,
    unnest(oast_decoded).timestamp as created_at,
    unnest(oast_decoded).machine_id as machine_id,
    unnest(oast_decoded).pid as pid,
    unnest(oast_decoded).campaign as campaign
FROM read_json('oast-data.ndjson')
WHERE oast_count > 0;
```

### 3. Campaign analysis

```sql
-- Find related domains by campaign identifier
WITH decoded AS (
    SELECT
        line_num,
        line,
        unnest(oast_decoded) as oast
    FROM read_json('oast-data.ndjson')
    WHERE oast_count > 0
)
SELECT
    oast.campaign as campaign,
    COUNT(*) as domain_count,
    COUNT(DISTINCT oast.machine_id) as unique_machines,
    MIN(oast.timestamp) as first_seen,
    MAX(oast.timestamp) as last_seen
FROM decoded
GROUP BY oast.campaign
ORDER BY domain_count DESC;
```

### 4. Machine ID correlation

```sql
-- Find domains from the same machine (shared scanner instance)
WITH decoded AS (
    SELECT
        line_num,
        unnest(oast_decoded) as oast
    FROM read_json('oast-data.ndjson')
    WHERE oast_count > 0
)
SELECT
    oast.machine_id as machine_id,
    COUNT(*) as domain_count,
    COUNT(DISTINCT oast.campaign) as unique_campaigns,
    LIST(DISTINCT oast.campaign) as campaigns
FROM decoded
GROUP BY oast.machine_id
ORDER BY domain_count DESC;
```

### 5. Timeline analysis

```sql
-- Activity timeline by hour
WITH decoded AS (
    SELECT
        line_num,
        line,
        unnest(oast_decoded) as oast
    FROM read_json('oast-data.ndjson')
    WHERE oast_count > 0
)
SELECT
    DATE_TRUNC('hour', CAST(oast.timestamp AS TIMESTAMP)) as hour,
    COUNT(*) as domain_count,
    COUNT(DISTINCT oast.machine_id) as unique_machines
FROM decoded
GROUP BY hour
ORDER BY hour;
```

### 6. Find multi-OAST lines

```sql
-- Lines with multiple OAST domains (potential mass scanning)
SELECT
    line_num,
    oast_count,
    substr(line, 1, 100) as line_preview
FROM read_json('oast-data.ndjson')
WHERE oast_count > 1
ORDER BY oast_count DESC;
```

### 7. K-sort analysis (temporal clustering)

```sql
-- Group by K-sort prefix (first 6 chars = timestamp-based sort key)
WITH decoded AS (
    SELECT
        line_num,
        unnest(oast_decoded) as oast
    FROM read_json('oast-data.ndjson')
    WHERE oast_count > 0
)
SELECT
    oast.ksort as ksort,
    COUNT(*) as domain_count,
    COUNT(DISTINCT oast.machine_id) as unique_machines,
    MIN(oast.timestamp) as earliest,
    MAX(oast.timestamp) as latest
FROM decoded
GROUP BY oast.ksort
ORDER BY domain_count DESC;
```

### 8. Export to Parquet for long-term storage

```sql
-- Convert NDJSON to Parquet with nested structure
COPY (
    SELECT * FROM read_json('oast-data.ndjson')
) TO 'oast-data.parquet' (FORMAT PARQUET);

-- Later, query the Parquet file
SELECT * FROM 'oast-data.parquet';
```

### 9. Join with original log lines

```sql
-- Find log context around OAST detections
WITH decoded AS (
    SELECT
        line_num,
        line,
        unnest(oast_decoded) as oast
    FROM read_json('oast-data.ndjson')
    WHERE oast_count > 0
),
all_lines AS (
    SELECT
        line_num,
        line
    FROM read_json('oast-data.ndjson')
)
SELECT
    d.line_num as detection_line,
    d.oast.campaign as campaign,
    l.line as context_line
FROM decoded d
LEFT JOIN all_lines l ON l.line_num BETWEEN d.line_num - 2 AND d.line_num + 2
ORDER BY d.line_num, l.line_num;
```

## Performance Tips

1. **Use `--skip-empty`** when processing large log files to reduce output size
2. **Filter early** in queries - use `WHERE oast_count > 0` before unnesting
3. **Create views** for commonly-used unnest patterns:
   ```sql
   CREATE VIEW oast_flat AS
   SELECT
       line_num,
       unnest(oast_decoded) as oast
   FROM read_json('oast-data.ndjson')
   WHERE oast_count > 0;

   -- Then query the view
   SELECT * FROM oast_flat WHERE oast.campaign = 'he008';
   ```
4. **Use Parquet** for large datasets to improve query performance

## Integration with Other Tools

### With jq for quick inspection

```bash
roast pipe -f logs.txt | jq 'select(.oast_count > 0) | .oast_decoded[].campaign' | sort | uniq -c
```

### With grep for filtering

```bash
roast pipe -f logs.txt | grep -F '"oast_count":1' | head -10
```

### Pipeline example

```bash
# Extract OASTs from logs, analyze with DuckDB, export to CSV
roast pipe -f /var/log/app.log --skip-empty | \
    duckdb -c "
        COPY (
            SELECT
                unnest(oast_decoded).original as subdomain,
                unnest(oast_decoded).timestamp as created_at,
                unnest(oast_decoded).campaign as campaign
            FROM read_json('/dev/stdin')
        ) TO '/dev/stdout' WITH (FORMAT CSV, HEADER)
    " > oast-report.csv
```
