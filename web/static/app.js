// app.js — vanilla JS client for roast web UI.
// No external dependencies. Handles tab switching, file upload/drag-drop,
// API calls, result rendering with classification badges, CSV export,
// and markdown report download.
//
// @decision: Vanilla JS over a framework because the UI is a single page with
// ~4 interactions. A framework would add build complexity for negligible benefit.

(function() {
  'use strict';

  // DOM refs
  const domainInput = document.getElementById('domain-input');
  const logTimestampInput = document.getElementById('log-timestamp');
  const actionSelect = document.getElementById('action-select');
  const submitBtn = document.getElementById('submit-btn');
  const resultsSection = document.getElementById('results-section');
  const resultsContainer = document.getElementById('results-container');
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');

  // Last result storage for CSV export
  let lastResultData = null;
  let lastResultAction = null;

  // Tab switching
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(tc => tc.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
  });

  // Drag and drop
  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) processFile(file);
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) processFile(fileInput.files[0]);
  });

  dropZone.addEventListener('click', e => {
    // Avoid double-triggering: the <label for="file-input"> already opens the dialog
    // natively, so only call fileInput.click() when the click didn't originate from
    // the label or file input itself.
    if (e.target === fileInput || e.target.closest('label[for="file-input"]')) return;
    fileInput.click();
  });

  function processFile(file) {
    const reader = new FileReader();
    reader.onload = function(e) {
      const text = e.target.result;
      // Try to extract domains from CSV columns
      const domains = extractDomainsFromCSV(text);
      domainInput.value = domains.join('\n');
      // Switch to paste tab to show loaded content
      tabs[0].click();
    };
    reader.readAsText(file);
  }

  function extractDomainsFromCSV(text) {
    const oastPattern = /[a-z0-9]{20,}[a-z0-9_-]*\.(?:oast\.(?:pro|live|site|online|fun|me)|interact\.sh|interactsh\.com)/gi;
    const domains = new Set();
    const matches = text.match(oastPattern);
    if (matches) {
      matches.forEach(m => domains.add(m.toLowerCase()));
    }
    // If no OAST pattern matches, return lines as-is (user might paste raw subdomains)
    if (domains.size === 0) {
      return text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    }
    return Array.from(domains);
  }

  // Submit
  submitBtn.addEventListener('click', async () => {
    const input = domainInput.value.trim();
    if (!input) return;

    const action = actionSelect.value;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Processing...';

    try {
      const requestBody = { input: input };

      // Include log_timestamp if provided
      const logTimestamp = logTimestampInput.value.trim();
      if (logTimestamp) {
        requestBody.log_timestamp = logTimestamp;
      }

      const resp = await fetch('/api/' + action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });

      const data = await resp.json();

      if (!resp.ok) {
        showError(data.error || 'Request failed');
        return;
      }

      renderResults(action, data);
    } catch (err) {
      showError('Network error: ' + err.message);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Analyze';
    }
  });

  function showError(msg) {
    resultsSection.hidden = false;
    resultsContainer.innerHTML = '<div class="error-msg">' + escapeHtml(msg) + '</div>';
  }

  function renderResults(action, data) {
    resultsSection.hidden = false;
    lastResultData = data;
    lastResultAction = action;

    switch (action) {
      case 'decode':
        renderDecodeResults(data);
        break;
      case 'classify':
        renderClassifyResults(data);
        break;
      case 'extract':
        renderExtractResults(data);
        break;
      case 'analyze':
        renderAnalyzeResults(data);
        break;
    }
  }

  // Download bar with Save CSV (and optionally Download Report) buttons
  function renderDownloadBar(action) {
    let html = '<div class="download-bar">';
    html += '<button class="download-csv-btn" onclick="return false;">Save CSV</button>';
    if (action === 'analyze') {
      html += ' <button class="download-report-btn" onclick="return false;">Download Report</button>';
    }
    html += '</div>';

    const bar = document.createElement('div');
    bar.innerHTML = html;
    resultsContainer.innerHTML = '';
    resultsContainer.appendChild(bar.firstChild);

    // Wire up CSV button
    const csvBtn = resultsContainer.querySelector('.download-csv-btn');
    if (csvBtn) {
      csvBtn.addEventListener('click', function() { downloadCSV(action); });
    }

    // Wire up Report button for analyze
    const reportBtn = resultsContainer.querySelector('.download-report-btn');
    if (reportBtn) {
      reportBtn.addEventListener('click', function() { downloadMarkdownReport(); });
    }
  }

  function renderDecodeResults(results) {
    if (!Array.isArray(results) || results.length === 0) {
      resultsContainer.innerHTML = '<p>No results</p>';
      return;
    }

    renderDownloadBar('decode');

    let html = '<table class="results-table"><thead><tr>';
    html += '<th>Original</th><th>Valid</th><th>Client</th><th>Version</th>';
    html += '<th>Conf</th><th>Timestamp</th><th>Machine</th><th>PID</th>';
    html += '<th>Counter</th><th>Nonce</th>';
    html += '</tr></thead><tbody>';

    for (const r of results) {
      const c = r.classification || {};
      html += '<tr>';
      html += '<td>' + escapeHtml(truncate(r.original, 35)) + '</td>';
      html += '<td>' + (r.valid ? 'Y' : 'N') + '</td>';
      html += '<td>' + clientBadge(c.client_type) + '</td>';
      html += '<td>' + versionBadge(c.server_version) + '</td>';
      html += '<td>' + confBadge(c.confidence) + '</td>';
      html += '<td>' + (r.valid ? formatTimestamp(r.timestamp) : '') + '</td>';
      html += '<td>' + escapeHtml(r.machine_id || '') + '</td>';
      html += '<td>' + (r.pid || '') + '</td>';
      html += '<td>' + (r.counter || '') + '</td>';
      html += '<td>' + escapeHtml(r.nonce || '') + '</td>';
      html += '</tr>';

      // Nonce analysis row
      if (c.nonce_analysis) {
        const na = c.nonce_analysis;
        html += '<tr><td colspan="10" class="nonce-detail">';
        html += 'Nonce: ts=' + formatTimestamp(na.nonce_timestamp);
        html += ' counter=' + na.nonce_counter;
        html += ' session_age=' + escapeHtml(na.session_age || '');
        if (na.commentary && na.commentary.length > 0) {
          html += '<br>' + na.commentary.map(escapeHtml).join('<br>');
        }
        html += '</td></tr>';
      }

      // Timezone estimate row
      if (r.timezone_estimate) {
        const tz = r.timezone_estimate;
        html += '<tr><td colspan="10" class="timezone-detail">';
        html += '<strong>Timezone:</strong> ' + escapeHtml(tz.utc_designation);
        html += ' (offset: ' + tz.offset_seconds + 's, confidence: ' + tz.confidence + ')';
        html += ' method: ' + tz.method;
        if (tz.reasoning && tz.reasoning.length > 0) {
          html += '<br>' + tz.reasoning.map(escapeHtml).join('<br>');
        }
        html += '</td></tr>';
      }
    }

    html += '</tbody></table>';
    resultsContainer.insertAdjacentHTML('beforeend', html);
  }

  function renderClassifyResults(results) {
    if (!Array.isArray(results) || results.length === 0) {
      resultsContainer.innerHTML = '<p>No results</p>';
      return;
    }

    renderDownloadBar('classify');

    let html = '<table class="results-table"><thead><tr>';
    html += '<th>Domain</th><th>Client</th><th>Version</th><th>Confidence</th>';
    html += '<th>Decodable</th><th>Reasoning</th>';
    html += '</tr></thead><tbody>';

    for (const r of results) {
      const c = r.classification || {};
      html += '<tr>';
      html += '<td>' + escapeHtml(truncate(r.domain, 40)) + '</td>';
      html += '<td>' + clientBadge(c.client_type) + '</td>';
      html += '<td>' + versionBadge(c.server_version) + '</td>';
      html += '<td>' + confBadge(c.confidence) + '</td>';
      html += '<td>' + (c.decodable ? 'Y' : 'N') + '</td>';
      html += '<td>' + (c.reasoning || []).map(escapeHtml).join('; ') + '</td>';
      html += '</tr>';
    }

    html += '</tbody></table>';
    resultsContainer.insertAdjacentHTML('beforeend', html);
  }

  function renderExtractResults(data) {
    const decoded = data.decoded || [];
    if (decoded.length === 0) {
      resultsContainer.innerHTML = '<p>No OAST domains found in text</p>';
      return;
    }
    // Store decoded for CSV export
    lastResultData = decoded;
    lastResultAction = 'extract';
    renderDecodeResults(decoded);
  }

  function renderAnalyzeResults(data) {
    renderDownloadBar('analyze');

    let html = '<div class="analysis-report">';

    if (data.executive_summary) {
      html += '<strong>Summary:</strong> ' + escapeHtml(data.executive_summary) + '<br><br>';
    }

    html += '<strong>Total Domains:</strong> ' + data.total_domains + '<br>';
    html += '<strong>Valid:</strong> ' + data.valid_domains;
    if (data.invalid_domains > 0) html += ' | <strong>Invalid:</strong> ' + data.invalid_domains;
    html += '<br>';
    html += '<strong>Campaigns:</strong> ' + data.unique_campaigns + '<br>';
    html += '<strong>Machines:</strong> ' + data.unique_machines + '<br>';
    html += '<strong>PIDs:</strong> ' + data.unique_pids + '<br>';

    if (data.time_span) {
      html += '<strong>Time Span:</strong> ' + escapeHtml(data.time_span) + '<br>';
    }

    // Classification summary
    if (data.client_types) {
      html += '<br><strong>Client Types:</strong> ';
      html += Object.entries(data.client_types).map(([k, v]) => clientBadge(k) + ' ' + v).join(' ');
      html += '<br>';
    }
    if (data.server_versions) {
      html += '<strong>Server Versions:</strong> ';
      html += Object.entries(data.server_versions).map(([k, v]) => versionBadge(k) + ' ' + v).join(' ');
      html += '<br>';
    }

    // Timezone consensus
    if (data.consensus_timezone) {
      const tz = data.consensus_timezone;
      html += '<br><strong>Consensus Timezone:</strong> ' + escapeHtml(tz.utc_designation);
      html += ' (confidence: ' + tz.confidence + ')<br>';
      if (tz.reasoning && tz.reasoning.length > 0) {
        html += '<em>' + tz.reasoning.slice(0, 2).map(escapeHtml).join(', ') + '</em><br>';
      }
    }

    // Cross-reference findings
    if (data.cross_ref_findings && data.cross_ref_findings.length > 0) {
      html += '<br><strong>Cross-Reference Findings:</strong><br>';
      data.cross_ref_findings.forEach(function(f) {
        html += '&bull; ' + escapeHtml(f) + '<br>';
      });
    }

    // Campaign details
    if (data.campaigns) {
      for (const [id, stats] of Object.entries(data.campaigns)) {
        html += '<br><strong>Campaign ' + escapeHtml(id) + ':</strong> ';
        html += stats.count + ' domains, ';
        html += 'counter ' + stats.counter_min + '-' + stats.counter_max;
        html += '<br>';
      }
    }

    html += '</div>';

    // --- Machine Clustering section ---
    if (data.machine_clusters && data.machine_clusters.length > 0) {
      html += '<div class="analysis-section">';
      html += '<h3 class="section-heading">Machine Clustering</h3>';
      html += '<p class="section-note">' + data.machine_clusters.length + ' distinct machine(s) identified</p>';
      html += '<table class="results-table"><thead><tr>';
      html += '<th>Machine ID</th><th>Domains</th><th>Campaigns</th><th>PIDs</th>';
      html += '<th>First Seen</th><th>Last Seen</th><th>Duration</th><th>Timezone</th>';
      html += '</tr></thead><tbody>';
      for (const cluster of data.machine_clusters) {
        const tz = cluster.timezone_consensus;
        html += '<tr>';
        html += '<td><code>' + escapeHtml(cluster.machine_id) + '</code></td>';
        html += '<td>' + cluster.domain_count + '</td>';
        html += '<td>' + (cluster.campaigns || []).map(escapeHtml).join(', ') + '</td>';
        html += '<td>' + (cluster.pids || []).join(', ') + '</td>';
        html += '<td>' + formatTimestamp(cluster.first_seen) + '</td>';
        html += '<td>' + formatTimestamp(cluster.last_seen) + '</td>';
        html += '<td>' + escapeHtml(cluster.duration || '') + '</td>';
        html += '<td>' + (tz ? escapeHtml(tz.utc_designation) + ' ' + confBadge(tz.confidence) : '') + '</td>';
        html += '</tr>';
      }
      html += '</tbody></table></div>';
    }

    // --- PID Lifecycle section ---
    if (data.pid_sessions && data.pid_sessions.length > 0) {
      html += '<div class="analysis-section">';
      html += '<h3 class="section-heading">PID Lifecycle</h3>';
      html += '<table class="results-table"><thead><tr>';
      html += '<th>PID</th><th>Machine</th><th>Domains</th>';
      html += '<th>First Seen</th><th>Last Seen</th><th>Duration</th><th>Counter Range</th>';
      html += '</tr></thead><tbody>';
      for (const session of data.pid_sessions) {
        html += '<tr>';
        html += '<td>' + session.pid + '</td>';
        html += '<td><code>' + escapeHtml(session.machine_id) + '</code></td>';
        html += '<td>' + session.domain_count + '</td>';
        html += '<td>' + formatTimestamp(session.first_seen) + '</td>';
        html += '<td>' + formatTimestamp(session.last_seen) + '</td>';
        html += '<td>' + escapeHtml(session.duration || '') + '</td>';
        html += '<td>' + (session.counter_range ? session.counter_range[0] + ' &ndash; ' + session.counter_range[1] : '') + '</td>';
        html += '</tr>';
      }
      html += '</tbody></table></div>';
    }

    // --- Counter Gap Analysis section ---
    const gaps = data.gap_analysis;
    if (gaps && gaps.total_gaps > 0) {
      html += '<div class="analysis-section">';
      html += '<h3 class="section-heading">Counter Gap Analysis</h3>';
      html += '<p class="section-note">' + gaps.total_gaps + ' gap(s) &mdash; ' + gaps.missing_domains + ' missing domain(s)</p>';
      html += '<table class="results-table"><thead><tr>';
      html += '<th>Machine</th><th>PID</th><th>Gap Start</th><th>Gap End</th>';
      html += '<th>Missing</th><th>Time Gap</th><th>Flag</th>';
      html += '</tr></thead><tbody>';
      for (const gap of (gaps.gaps || [])) {
        const suspiciousFlag = gap.suspicious
          ? '<span class="badge badge-medium">SUSPICIOUS</span>'
          : '';
        html += '<tr>';
        html += '<td><code>' + escapeHtml(gap.machine_id) + '</code></td>';
        html += '<td>' + gap.pid + '</td>';
        html += '<td>' + gap.start_counter + '</td>';
        html += '<td>' + gap.end_counter + '</td>';
        html += '<td>' + gap.gap_size + '</td>';
        html += '<td>' + gap.time_gap_secs + 's</td>';
        html += '<td>' + suspiciousFlag + '</td>';
        html += '</tr>';
      }
      html += '</tbody></table></div>';
    }

    // --- Temporal Analysis section ---
    if (data.temporal_profiles && data.temporal_profiles.length > 0) {
      html += '<div class="analysis-section">';
      html += '<h3 class="section-heading">Temporal Analysis</h3>';
      html += '<table class="results-table"><thead><tr>';
      html += '<th>Machine</th><th>Mean Interval</th><th>Std Dev</th><th>Bursts</th>';
      html += '<th>Quiet Periods</th><th>Automated</th><th>Active Hours</th><th>Active Days</th>';
      html += '</tr></thead><tbody>';
      for (const tp of data.temporal_profiles) {
        if (!tp) continue;
        const activeHours = tp.active_hours && tp.active_hours.length > 0
          ? tp.active_hours[0] + ':00&ndash;' + tp.active_hours[tp.active_hours.length - 1] + ':00'
          : '';
        const activeDays = tp.active_days && tp.active_days.length > 0
          ? tp.active_days.map(escapeHtml).join(', ')
          : '';
        html += '<tr>';
        html += '<td><code>' + escapeHtml(tp.machine_id) + '</code></td>';
        html += '<td>' + (tp.mean_interval_secs || 0).toFixed(1) + 's</td>';
        html += '<td>' + (tp.stddev_interval_secs || 0).toFixed(1) + 's</td>';
        html += '<td>' + (tp.burst_count || 0) + '</td>';
        html += '<td>' + (tp.quiet_periods || 0) + '</td>';
        html += '<td>' + automatedBadge(tp.automated_likelihood) + '</td>';
        html += '<td>' + activeHours + '</td>';
        html += '<td>' + activeDays + '</td>';
        html += '</tr>';
        // Reasoning sub-row
        if (tp.reasoning && tp.reasoning.length > 0) {
          html += '<tr><td colspan="8" class="nonce-detail">';
          html += tp.reasoning.map(escapeHtml).join(' &bull; ');
          html += '</td></tr>';
        }
      }
      html += '</tbody></table></div>';
    }

    // --- Attribution Profiles section (prominent — key forensic output) ---
    if (data.attribution_profiles && data.attribution_profiles.length > 0) {
      html += '<div class="analysis-section attribution-section">';
      html += '<h3 class="section-heading">Attribution Profiles</h3>';
      for (const ap of data.attribution_profiles) {
        if (!ap) continue;
        html += '<div class="attribution-card">';
        html += '<div class="attribution-header">';
        html += '<code>' + escapeHtml(ap.machine_id) + '</code> ';
        html += confBadge(ap.overall_confidence);
        html += '</div>';
        html += '<p class="attribution-narrative">' + escapeHtml(ap.narrative || '') + '</p>';
        html += '</div>';
      }
      html += '</div>';
    }

    resultsContainer.insertAdjacentHTML('beforeend', html);
  }

  // automatedBadge returns a coloured badge for automated likelihood level.
  // high=orange (medium CSS), medium=teal (v102 CSS), low=grey (unknown CSS).
  function automatedBadge(level) {
    if (!level) return '';
    const cls = { high: 'badge-medium', medium: 'badge-v102', low: 'badge-unknown' }[level] || 'badge-unknown';
    return '<span class="badge ' + cls + '">' + escapeHtml(level) + '</span>';
  }

  // CSV generation and download
  function downloadCSV(action) {
    if (!lastResultData) return;

    let csv = '';
    const data = lastResultData;

    if (action === 'decode' || action === 'extract') {
      const results = Array.isArray(data) ? data : (data.decoded || []);
      const headers = ['Original', 'Valid', 'Timestamp', 'MachineID', 'PID', 'Counter',
        'KSort', 'Campaign', 'Nonce', 'ClientType', 'ServerVersion', 'Decodable',
        'Confidence', 'NonceTimestamp', 'NonceCounter', 'Error'];
      csv = headers.join(',') + '\n';
      for (const r of results) {
        const c = r.classification || {};
        const row = [
          csvEscape(r.original || ''),
          r.valid ? 'true' : 'false',
          r.valid ? formatTimestamp(r.timestamp) : '',
          csvEscape(r.machine_id || ''),
          r.pid || '',
          r.counter || '',
          csvEscape(r.ksort || ''),
          csvEscape(r.campaign || ''),
          csvEscape(r.nonce || ''),
          c.client_type || '',
          c.server_version || '',
          c.decodable ? 'true' : 'false',
          c.confidence || '',
          r.nonce_timestamp ? formatTimestamp(r.nonce_timestamp) : '',
          r.nonce_counter != null ? r.nonce_counter : '',
          csvEscape(r.error || '')
        ];
        csv += row.join(',') + '\n';
      }
    } else if (action === 'classify') {
      const headers = ['Domain', 'ClientType', 'ServerVersion', 'Confidence', 'Decodable', 'Reasoning'];
      csv = headers.join(',') + '\n';
      for (const r of data) {
        const c = r.classification || {};
        const row = [
          csvEscape(r.domain || ''),
          c.client_type || '',
          c.server_version || '',
          c.confidence || '',
          c.decodable ? 'true' : 'false',
          csvEscape((c.reasoning || []).join('; '))
        ];
        csv += row.join(',') + '\n';
      }
    } else if (action === 'analyze') {
      // One row per machine cluster with all analytics fields flattened.
      // Falls back to a summary row if no clusters are present.
      const clusters = data.machine_clusters || [];

      // Build lookup maps by machine_id
      const temporalMap = {};
      for (const tp of (data.temporal_profiles || [])) {
        if (tp && tp.machine_id) temporalMap[tp.machine_id] = tp;
      }
      const attrMap = {};
      for (const ap of (data.attribution_profiles || [])) {
        if (ap && ap.machine_id) attrMap[ap.machine_id] = ap;
      }
      const gapCountMap = (data.gap_analysis && data.gap_analysis.per_machine_gaps) || {};
      const missingMap = {};
      for (const gap of ((data.gap_analysis && data.gap_analysis.gaps) || [])) {
        missingMap[gap.machine_id] = (missingMap[gap.machine_id] || 0) + gap.gap_size;
      }

      const headers = [
        'machine_id', 'campaigns', 'pids', 'domain_count',
        'first_seen', 'last_seen', 'duration', 'velocity_per_hour',
        'counter_min', 'counter_max',
        'timezone_offset', 'timezone_utc', 'timezone_confidence',
        'mean_interval_secs', 'stddev_interval_secs', 'burst_count',
        'quiet_periods', 'automated_likelihood', 'active_hours', 'active_days',
        'attribution_confidence', 'attribution_narrative',
        'counter_gaps_count', 'total_missing_domains'
      ];
      csv = headers.join(',') + '\n';

      if (clusters.length > 0) {
        for (const c of clusters) {
          const mid = c.machine_id || '';
          const tz = c.timezone_consensus || {};
          const tp = temporalMap[mid] || {};
          const ap = attrMap[mid] || {};
          const row = [
            csvEscape(mid),
            csvEscape((c.campaigns || []).join(' ')),
            csvEscape((c.pids || []).join(' ')),
            c.domain_count || 0,
            c.first_seen ? formatTimestamp(c.first_seen) : '',
            c.last_seen ? formatTimestamp(c.last_seen) : '',
            csvEscape(c.duration || ''),
            (c.velocity || 0).toFixed(2),
            c.counter_range ? c.counter_range[0] : '',
            c.counter_range ? c.counter_range[1] : '',
            tz.offset_seconds != null ? tz.offset_seconds : '',
            csvEscape(tz.utc_designation || ''),
            tz.confidence || '',
            tp.mean_interval_secs != null ? tp.mean_interval_secs.toFixed(2) : '',
            tp.stddev_interval_secs != null ? tp.stddev_interval_secs.toFixed(2) : '',
            tp.burst_count != null ? tp.burst_count : '',
            tp.quiet_periods != null ? tp.quiet_periods : '',
            tp.automated_likelihood || '',
            csvEscape((tp.active_hours || []).join(' ')),
            csvEscape((tp.active_days || []).join(' ')),
            ap.overall_confidence || '',
            csvEscape(ap.narrative || ''),
            gapCountMap[mid] != null ? gapCountMap[mid] : 0,
            missingMap[mid] != null ? missingMap[mid] : 0
          ];
          csv += row.join(',') + '\n';
        }
      } else {
        // Fallback: single summary row when no cluster data available
        const row = [
          '(summary)', '', '', data.valid_domains || 0,
          data.first_seen ? formatTimestamp(data.first_seen) : '',
          data.last_seen ? formatTimestamp(data.last_seen) : '',
          csvEscape(data.time_span || ''),
          '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''
        ];
        csv += row.join(',') + '\n';
      }
    }

    triggerDownload(csv, 'text/csv', 'roast-' + action + '.csv');
  }

  // Markdown report download (analyze only)
  async function downloadMarkdownReport() {
    const input = domainInput.value.trim();
    if (!input) return;

    try {
      const resp = await fetch('/api/analyze/markdown', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: input })
      });

      if (!resp.ok) {
        const err = await resp.json();
        showError(err.error || 'Failed to generate report');
        return;
      }

      const markdown = await resp.text();
      triggerDownload(markdown, 'text/markdown', 'roast-report.md');
    } catch (err) {
      showError('Network error: ' + err.message);
    }
  }

  function triggerDownload(content, mimeType, filename) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function csvEscape(s) {
    if (!s) return '';
    s = String(s);
    if (s.indexOf(',') >= 0 || s.indexOf('"') >= 0 || s.indexOf('\n') >= 0) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  // Helpers
  function clientBadge(type_) {
    if (!type_) return '';
    const cls = { cli: 'badge-cli', web: 'badge-web', unknown: 'badge-unknown' }[type_] || 'badge-unknown';
    return '<span class="badge ' + cls + '">' + escapeHtml(type_) + '</span>';
  }

  function versionBadge(ver) {
    if (!ver) return '';
    const cls = ver === 'v1.0.1' ? 'badge-v101' : ver === 'v1.0.2+' ? 'badge-v102' : 'badge-unknown';
    return '<span class="badge ' + cls + '">' + escapeHtml(ver) + '</span>';
  }

  function confBadge(conf) {
    if (!conf) return '';
    const cls = { high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }[conf] || 'badge-unknown';
    return '<span class="badge ' + cls + '">' + escapeHtml(conf) + '</span>';
  }

  function formatTimestamp(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return escapeHtml(ts);
    return d.toISOString().replace('T', ' ').substring(0, 19);
  }

  function truncate(s, max) {
    if (!s) return '';
    return s.length > max ? s.substring(0, max - 3) + '...' : s;
  }

  function escapeHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
})();
