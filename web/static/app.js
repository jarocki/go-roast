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
      const resp = await fetch('/api/' + action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: input })
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

    // Cross-reference findings
    if (data.cross_ref_findings && data.cross_ref_findings.length > 0) {
      html += '<br><strong>Cross-Reference Findings:</strong><br>';
      data.cross_ref_findings.forEach(function(f) {
        html += '- ' + escapeHtml(f) + '<br>';
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
    resultsContainer.insertAdjacentHTML('beforeend', html);
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
      const headers = ['Metric', 'Value'];
      csv = headers.join(',') + '\n';
      csv += 'TotalDomains,' + data.total_domains + '\n';
      csv += 'ValidDomains,' + data.valid_domains + '\n';
      csv += 'InvalidDomains,' + data.invalid_domains + '\n';
      csv += 'UniqueCampaigns,' + data.unique_campaigns + '\n';
      csv += 'UniqueMachines,' + data.unique_machines + '\n';
      csv += 'UniquePIDs,' + data.unique_pids + '\n';
      if (data.time_span) csv += 'TimeSpan,' + csvEscape(data.time_span) + '\n';
      if (data.executive_summary) csv += 'ExecutiveSummary,' + csvEscape(data.executive_summary) + '\n';
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
