// app.js — vanilla JS client for roast web UI.
// No external dependencies. Handles tab switching, file upload/drag-drop,
// API calls, result rendering with classification badges, CSV export,
// and markdown report download.
//
// @decision: Vanilla JS over a framework because the UI is a single page with
// ~4 interactions. A framework would add build complexity for negligible benefit.
//
// @decision DEC-UI-001
// @title Event delegation on resultsContainer for all dynamic table interactions
// @status accepted
// @rationale Table rows are replaced on every render. Attaching listeners
// directly to rows would leak memory and require re-wiring after every render.
// A single delegated listener on the stable resultsContainer parent handles
// accordion toggles, sort header clicks, group collapse, filter input, and
// group-by select regardless of how many times the table is re-rendered.
//
// @decision DEC-UI-002
// @title Module-level state for filter/sort/group coordination
// @status accepted
// @rationale originalResults, currentResults, sortState, currentFilter, and
// currentGroupBy are stored at module scope so applyFilterSortGroup() can
// coordinate them without threading state through every render function call.
//
// @decision DEC-UI-003
// @title datetime-local + Z suffix for RFC3339 UTC timestamp
// @status accepted
// @rationale The datetime-local input stores a naive local time string with no
// timezone. Appending Z on submit is the correct interpretation as UTC for the
// backend. The Now button uses UTC fields of the Date object to produce the
// correct UTC time string regardless of the user's local timezone.

(function() {
  'use strict';

  // ── DOM refs ──────────────────────────────────────────────────────────────

  const domainInput       = document.getElementById('domain-input');
  const logTimestampInput = document.getElementById('log-timestamp');
  const tsNowBtn          = document.getElementById('ts-now-btn');
  const tsClearBtn        = document.getElementById('ts-clear-btn');
  const tsNoticeEl        = document.getElementById('ts-autodetect-notice');
  const actionSelect      = document.getElementById('action-select');
  const submitBtn         = document.getElementById('submit-btn');
  const resultsSection    = document.getElementById('results-section');
  const resultsContainer  = document.getElementById('results-container');
  const dropZone          = document.getElementById('drop-zone');
  const fileInput         = document.getElementById('file-input');
  const tabs              = document.querySelectorAll('.tab');
  const tabContents       = document.querySelectorAll('.tab-content');

  // ── Module-level state ────────────────────────────────────────────────────

  let lastResultData       = null;
  let lastResultAction     = null;
  let sortState            = { col: null, dir: null };
  let originalResults      = [];
  let currentResults       = [];
  let currentFilter        = '';
  let currentGroupBy       = '';
  let tsNoticeDismissTimer = null;

  // ── Tab switching ─────────────────────────────────────────────────────────

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(tc => tc.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
  });

  // ── Drag and drop ─────────────────────────────────────────────────────────

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

  // ── Timestamp helpers ─────────────────────────────────────────────────────

  // toDatetimeLocalString converts a Date to YYYY-MM-DDTHH:mm:ss using UTC
  // fields. Used to populate the datetime-local input, which expects no Z suffix.
  function toDatetimeLocalString(date) {
    const pad = n => String(n).padStart(2, '0');
    return date.getUTCFullYear() + '-'
      + pad(date.getUTCMonth() + 1) + '-'
      + pad(date.getUTCDate()) + 'T'
      + pad(date.getUTCHours()) + ':'
      + pad(date.getUTCMinutes()) + ':'
      + pad(date.getUTCSeconds());
  }

  // detectTimestampFromText inspects arbitrary log text and returns a
  // datetime-local format string (YYYY-MM-DDTHH:mm:ss, UTC) or null if nothing
  // recognisable is found. Patterns tried in priority order:
  //   1. ISO 8601:   2025-02-15T21:00:00 or 2025-02-15 21:00:00
  //   2. Zeek epoch: 1700000000.123456 at the start of a line
  //   3. Apache/nginx: [15/Feb/2025:21:00:00 +0000]
  //   4. Syslog:     Feb 15 21:00:00 (assume current UTC year)
  function detectTimestampFromText(text) {
    // 1. ISO 8601
    const isoMatch = text.match(/(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})/);
    if (isoMatch) {
      return isoMatch[1] + 'T' + isoMatch[2];
    }

    // 2. Zeek epoch float (epoch 1500000000+ covers 2017 onward)
    const zeekMatch = text.match(/(?:^|\n)(1[5-9]\d{8}\.\d+)/m);
    if (zeekMatch) {
      const epoch = parseFloat(zeekMatch[1]);
      if (!isNaN(epoch)) {
        return toDatetimeLocalString(new Date(epoch * 1000));
      }
    }

    // 3. Apache/nginx combined log: [15/Feb/2025:21:00:00 +0000]
    const apacheMatch = text.match(/\[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})\s[+-]\d{4}\]/);
    if (apacheMatch) {
      const months = { Jan:0, Feb:1, Mar:2, Apr:3, May:4, Jun:5,
                       Jul:6, Aug:7, Sep:8, Oct:9, Nov:10, Dec:11 };
      const month = months[apacheMatch[2]];
      if (month !== undefined) {
        const d = new Date(Date.UTC(
          parseInt(apacheMatch[3], 10), month,
          parseInt(apacheMatch[1], 10),
          parseInt(apacheMatch[4].slice(0, 2), 10),
          parseInt(apacheMatch[4].slice(3, 5), 10),
          parseInt(apacheMatch[4].slice(6, 8), 10)
        ));
        return toDatetimeLocalString(d);
      }
    }

    // 4. Syslog: Feb 15 21:00:00 (current UTC year assumed)
    const syslogMatch = text.match(/^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})/m);
    if (syslogMatch) {
      const months = { Jan:0, Feb:1, Mar:2, Apr:3, May:4, Jun:5,
                       Jul:6, Aug:7, Sep:8, Oct:9, Nov:10, Dec:11 };
      const month = months[syslogMatch[1]];
      if (month !== undefined) {
        const now = new Date();
        const d = new Date(Date.UTC(
          now.getUTCFullYear(), month,
          parseInt(syslogMatch[2], 10),
          parseInt(syslogMatch[3].slice(0, 2), 10),
          parseInt(syslogMatch[3].slice(3, 5), 10),
          parseInt(syslogMatch[3].slice(6, 8), 10)
        ));
        return toDatetimeLocalString(d);
      }
    }

    return null;
  }

  // showTsNotice displays a transient notice in the ts-autodetect-notice span
  // and auto-dismisses after 3 seconds.
  function showTsNotice(msg) {
    if (tsNoticeDismissTimer) clearTimeout(tsNoticeDismissTimer);
    tsNoticeEl.textContent = msg;
    tsNoticeEl.hidden = false;
    tsNoticeDismissTimer = setTimeout(function() {
      tsNoticeEl.hidden = true;
      tsNoticeEl.textContent = '';
      tsNoticeDismissTimer = null;
    }, 3000);
  }

  // "Now" button — fills datetime-local with current UTC time
  tsNowBtn.addEventListener('click', function() {
    logTimestampInput.value = toDatetimeLocalString(new Date());
  });

  // "Clear" button — empties the field and cancels any pending notice
  tsClearBtn.addEventListener('click', function() {
    logTimestampInput.value = '';
    tsNoticeEl.hidden = true;
    if (tsNoticeDismissTimer) {
      clearTimeout(tsNoticeDismissTimer);
      tsNoticeDismissTimer = null;
    }
  });

  // Auto-detect timestamp when user pastes/types in the domain textarea
  domainInput.addEventListener('input', function() {
    if (logTimestampInput.value) return; // only fill when empty
    const detected = detectTimestampFromText(domainInput.value);
    if (detected) {
      logTimestampInput.value = detected;
      showTsNotice('Timestamp auto-detected from log text');
    }
  });

  // ── File processing ───────────────────────────────────────────────────────

  function processFile(file) {
    const reader = new FileReader();
    reader.onload = function(e) {
      const text = e.target.result;
      const domains = extractDomainsFromCSV(text);
      domainInput.value = domains.join('\n');
      // Switch to paste tab to show loaded content
      tabs[0].click();
      // Auto-detect timestamp from file contents if field is empty
      if (!logTimestampInput.value) {
        const detected = detectTimestampFromText(text);
        if (detected) {
          logTimestampInput.value = detected;
          showTsNotice('Timestamp auto-detected from file');
        }
      }
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

  // ── Submit ────────────────────────────────────────────────────────────────

  submitBtn.addEventListener('click', async () => {
    const input = domainInput.value.trim();
    if (!input) return;

    const action = actionSelect.value;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Processing...';

    try {
      const requestBody = { input: input };

      // Include log_timestamp if provided. Append Z to the datetime-local value
      // to produce a valid RFC3339 UTC timestamp for the backend (DEC-UI-003).
      const logTimestamp = logTimestampInput.value.trim();
      if (logTimestamp) {
        requestBody.log_timestamp = logTimestamp + 'Z';
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

  // ── Download bar ──────────────────────────────────────────────────────────

  // renderDownloadBar creates the Save CSV (and Download Report) buttons,
  // clears resultsContainer, and wires click handlers.
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

    const csvBtn = resultsContainer.querySelector('.download-csv-btn');
    if (csvBtn) {
      csvBtn.addEventListener('click', function() { downloadCSV(action); });
    }

    const reportBtn = resultsContainer.querySelector('.download-report-btn');
    if (reportBtn) {
      reportBtn.addEventListener('click', function() { downloadMarkdownReport(); });
    }
  }

  // ── Decode results ────────────────────────────────────────────────────────

  // renderDecodeResults is the entry point for decode/extract results.
  // Resets module state, then delegates to toolbar + table renders.
  function renderDecodeResults(results) {
    if (!Array.isArray(results) || results.length === 0) {
      resultsContainer.innerHTML = '<p>No results</p>';
      return;
    }

    originalResults = results;
    currentResults  = results.slice();
    currentFilter   = '';
    currentGroupBy  = '';
    sortState       = { col: null, dir: null };

    renderDownloadBar('decode');
    renderDecodeToolbar();
    renderDecodeTable(currentResults);
  }

  // renderDecodeToolbar appends the filter input, count span, and group-by
  // select to resultsContainer.
  function renderDecodeToolbar() {
    const toolbar = document.createElement('div');
    toolbar.className = 'table-toolbar';
    toolbar.id = 'decode-toolbar';
    toolbar.innerHTML =
      '<input class="table-filter" id="decode-filter" placeholder="Filter rows...">' +
      '<span class="filter-count" id="decode-filter-count"></span>' +
      '<select id="decode-groupby" class="groupby-select">' +
        '<option value="">No Grouping</option>' +
        '<option value="machine_id">Machine ID</option>' +
        '<option value="campaign">Campaign</option>' +
        '<option value="client_type">Client Type</option>' +
        '<option value="server_version">Server Version</option>' +
      '</select>';
    resultsContainer.appendChild(toolbar);
    updateFilterCount(originalResults.length, originalResults.length);
  }

  // renderDecodeTable creates or replaces the results-table element.
  // Column order (13 total):
  //   toggle | Original | Valid | Client | Version | Conf |
  //   Timestamp | Machine | PID | Counter | Nonce | Nonce TS | Nonce #
  function renderDecodeTable(results) {
    const colCount = 13;

    const existing = resultsContainer.querySelector('.results-table');
    if (existing) existing.remove();

    const table = document.createElement('table');
    table.className = 'results-table';

    // thead
    const headerCols = [
      { label: '',          key: null },
      { label: 'Original',  key: 'original' },
      { label: 'Valid',     key: 'valid' },
      { label: 'Client',    key: 'client_type' },
      { label: 'Version',   key: 'server_version' },
      { label: 'Conf',      key: 'confidence' },
      { label: 'Timestamp', key: 'timestamp' },
      { label: 'Machine',   key: 'machine_id' },
      { label: 'PID',       key: 'pid' },
      { label: 'Counter',   key: 'counter' },
      { label: 'Nonce',     key: 'nonce' },
      { label: 'Nonce TS',  key: 'nonce_ts' },
      { label: 'Nonce #',   key: 'nonce_counter' }
    ];

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    for (const col of headerCols) {
      const th = document.createElement('th');
      th.textContent = col.label;
      if (col.key) {
        th.dataset.sortCol = col.key;
        if (sortState.col === col.key) {
          th.dataset.sortDir = sortState.dir;
        }
      }
      headerRow.appendChild(th);
    }
    thead.appendChild(headerRow);
    table.appendChild(thead);

    // tbody
    const tbody = document.createElement('tbody');
    tbody.id = 'decode-tbody';

    if (currentGroupBy) {
      renderGroupedRows(results, currentGroupBy, colCount, tbody);
    } else {
      results.forEach(function(r, idx) {
        const pair = renderDataRow(r, idx, colCount);
        tbody.appendChild(pair.dataRow);
        tbody.appendChild(pair.accordionRow);
      });
    }

    table.appendChild(tbody);
    resultsContainer.appendChild(table);
    updateFilterCount(results.length, originalResults.length);
  }

  // renderDataRow builds one visible data-row <tr> and its hidden
  // accordion-row <tr>. Returns { dataRow, accordionRow }.
  function renderDataRow(r, idx, colCount) {
    const c = r.classification || {};

    const dataRow = document.createElement('tr');
    dataRow.className = 'data-row';
    dataRow.dataset.rowIdx = idx;

    // Toggle cell
    const toggleTd = document.createElement('td');
    const toggleSpan = document.createElement('span');
    toggleSpan.className = 'accordion-toggle';
    toggleSpan.dataset.accordionToggle = '';
    toggleSpan.textContent = '\u25b6';
    toggleTd.appendChild(toggleSpan);
    dataRow.appendChild(toggleTd);

    // Original — full value in title, ellipsis via CSS
    const origTd = document.createElement('td');
    origTd.className = 'col-original';
    origTd.title = r.original || '';
    origTd.textContent = r.original || '';
    dataRow.appendChild(origTd);

    appendTd(dataRow, r.valid ? 'Y' : 'N');

    const clientTd = document.createElement('td');
    clientTd.innerHTML = clientBadge(c.client_type);
    dataRow.appendChild(clientTd);

    const verTd = document.createElement('td');
    verTd.innerHTML = versionBadge(c.server_version);
    dataRow.appendChild(verTd);

    const confTd = document.createElement('td');
    confTd.innerHTML = confBadge(c.confidence);
    dataRow.appendChild(confTd);

    appendTd(dataRow, r.valid ? formatTimestamp(r.timestamp) : '');
    appendTd(dataRow, r.machine_id || '');
    appendTd(dataRow, r.pid != null ? r.pid : '');
    appendTd(dataRow, r.counter != null ? r.counter : '');
    appendTd(dataRow, r.nonce || '');
    // Nonce TS and Nonce # — promoted fields, omitempty in JSON
    appendTd(dataRow, r.nonce_timestamp ? formatTimestamp(r.nonce_timestamp) : '');
    appendTd(dataRow, r.nonce_counter != null ? r.nonce_counter : '');

    // Accordion row
    const accordionRow = document.createElement('tr');
    accordionRow.className = 'accordion-row';
    const accordionTd = document.createElement('td');
    accordionTd.className = 'accordion-cell';
    accordionTd.colSpan = colCount;
    accordionTd.innerHTML = renderAccordionContent(r);
    accordionRow.appendChild(accordionTd);

    return { dataRow: dataRow, accordionRow: accordionRow };
  }

  // appendTd creates a plain text <td> and appends it to row.
  function appendTd(row, text) {
    const td = document.createElement('td');
    td.textContent = String(text);
    row.appendChild(td);
  }

  // renderAccordionContent returns the HTML string for the accordion body.
  // Sections: Nonce Analysis, Timezone Estimate, Classification Reasoning,
  // Full JSON (always present).
  function renderAccordionContent(r) {
    const c = r.classification || {};
    let html = '';

    if (c.nonce_analysis) {
      const na = c.nonce_analysis;
      html += '<div class="accordion-section">';
      html += '<div class="accordion-section-title">Nonce Analysis</div>';
      html += '<div>ts: ' + escapeHtml(formatTimestamp(na.nonce_timestamp)) + '</div>';
      html += '<div>counter: ' + escapeHtml(String(na.nonce_counter != null ? na.nonce_counter : '')) + '</div>';
      html += '<div>session_age: ' + escapeHtml(na.session_age || '') + '</div>';
      if (na.commentary && na.commentary.length > 0) {
        html += '<ul>' + na.commentary.map(function(s) { return '<li>' + escapeHtml(s) + '</li>'; }).join('') + '</ul>';
      }
      html += '</div>';
    }

    if (r.timezone_estimate) {
      const tz = r.timezone_estimate;
      html += '<div class="accordion-section">';
      html += '<div class="accordion-section-title">Timezone Estimate</div>';
      html += '<div>designation: ' + escapeHtml(tz.utc_designation || '') + '</div>';
      html += '<div>offset: ' + escapeHtml(String(tz.offset_seconds != null ? tz.offset_seconds : '')) + 's</div>';
      html += '<div>confidence: ' + escapeHtml(tz.confidence || '') + '</div>';
      html += '<div>method: ' + escapeHtml(tz.method || '') + '</div>';
      if (tz.reasoning && tz.reasoning.length > 0) {
        html += '<ul>' + tz.reasoning.map(function(s) { return '<li>' + escapeHtml(s) + '</li>'; }).join('') + '</ul>';
      }
      html += '</div>';
    }

    if (c.reasoning && c.reasoning.length > 0) {
      html += '<div class="accordion-section">';
      html += '<div class="accordion-section-title">Classification Reasoning</div>';
      html += '<ul>' + c.reasoning.map(function(s) { return '<li>' + escapeHtml(s) + '</li>'; }).join('') + '</ul>';
      html += '</div>';
    }

    html += '<div class="accordion-section">';
    html += '<div class="accordion-section-title">Full JSON</div>';
    html += '<pre class="json-dump">' + escapeHtml(JSON.stringify(r, null, 2)) + '</pre>';
    html += '</div>';

    return html;
  }

  // renderGroupedRows inserts group-header <tr>s between groups of data rows.
  function renderGroupedRows(results, groupKey, colCount, tbody) {
    const groupMap = new Map();
    for (const r of results) {
      const c = r.classification || {};
      let key;
      if (groupKey === 'client_type')         key = c.client_type    || '(unknown)';
      else if (groupKey === 'server_version') key = c.server_version || '(unknown)';
      else                                    key = r[groupKey]      || '(unknown)';
      if (!groupMap.has(key)) groupMap.set(key, []);
      groupMap.get(key).push(r);
    }

    const groupLabels = {
      machine_id: 'Machine', campaign: 'Campaign',
      client_type: 'Client', server_version: 'Version'
    };
    const label = groupLabels[groupKey] || groupKey;

    let groupIdx = 0;
    for (const [groupVal, rows] of groupMap) {
      const headerRow = document.createElement('tr');
      headerRow.className = 'group-header';
      headerRow.dataset.groupIdx = groupIdx;
      const headerTd = document.createElement('td');
      headerTd.colSpan = colCount;
      headerTd.textContent = label + ': ' + groupVal
        + ' (' + rows.length + ' row' + (rows.length !== 1 ? 's' : '') + ')';
      headerRow.appendChild(headerTd);
      tbody.appendChild(headerRow);

      rows.forEach(function(r, rowIdx) {
        const pair = renderDataRow(r, groupIdx * 10000 + rowIdx, colCount);
        pair.dataRow.dataset.groupIdx = groupIdx;
        pair.accordionRow.dataset.groupIdx = groupIdx;
        tbody.appendChild(pair.dataRow);
        tbody.appendChild(pair.accordionRow);
      });

      groupIdx++;
    }
  }

  // ── Sort / filter / group coordination ───────────────────────────────────

  // applyFilterSortGroup: filter originalResults → sort → re-render table.
  // Called whenever filter text, sort state, or group-by changes.
  function applyFilterSortGroup() {
    const q = currentFilter.toLowerCase();
    let filtered = originalResults;
    if (q) {
      filtered = originalResults.filter(function(r) {
        const c = r.classification || {};
        const parts = [
          r.original || '',
          r.machine_id || '',
          r.campaign || '',
          c.client_type || '',
          c.server_version || '',
          r.valid ? formatTimestamp(r.timestamp) : '',
          r.nonce || ''
        ];
        return parts.some(function(p) { return p.toLowerCase().indexOf(q) >= 0; });
      });
    }

    if (sortState.col) {
      const dir = sortState.dir === 'asc' ? 1 : -1;
      filtered = filtered.slice().sort(function(a, b) {
        const va = getSortValue(a, sortState.col);
        const vb = getSortValue(b, sortState.col);
        if (va < vb) return -dir;
        if (va > vb) return  dir;
        return 0;
      });
    }

    currentResults = filtered;
    renderDecodeTable(filtered);
  }

  // getSortValue maps a column sort key to a comparable value for row r.
  function getSortValue(r, col) {
    const c = r.classification || {};
    const confOrder = { high: 3, medium: 2, low: 1 };
    switch (col) {
      case 'original':       return (r.original || '').toLowerCase();
      case 'valid':          return r.valid ? 1 : 0;
      case 'client_type':    return (c.client_type || '').toLowerCase();
      case 'server_version': return (c.server_version || '').toLowerCase();
      case 'confidence':     return confOrder[c.confidence] || 0;
      case 'timestamp':      return r.timestamp ? new Date(r.timestamp).getTime() : 0;
      case 'machine_id':     return (r.machine_id || '').toLowerCase();
      case 'pid':            return r.pid || 0;
      case 'counter':        return r.counter || 0;
      case 'nonce':          return (r.nonce || '').toLowerCase();
      case 'nonce_ts':       return r.nonce_timestamp ? new Date(r.nonce_timestamp).getTime() : 0;
      case 'nonce_counter':  return r.nonce_counter != null ? r.nonce_counter : -1;
      default:               return '';
    }
  }

  // updateFilterCount updates the #decode-filter-count span.
  function updateFilterCount(shown, total) {
    const el = document.getElementById('decode-filter-count');
    if (!el) return;
    el.textContent = shown === total
      ? total + ' rows'
      : shown + ' of ' + total + ' rows';
  }

  // ── Event delegation on resultsContainer ─────────────────────────────────

  resultsContainer.addEventListener('click', function(e) {
    // Accordion toggle
    const toggle = e.target.closest('[data-accordion-toggle]');
    if (toggle) {
      const dataRow = toggle.closest('.data-row');
      if (dataRow) {
        const wasExpanded = dataRow.classList.contains('expanded');
        dataRow.classList.toggle('expanded', !wasExpanded);
        toggle.textContent = wasExpanded ? '\u25b6' : '\u25bc';
      }
      return;
    }

    // Sort header click
    const th = e.target.closest('th[data-sort-col]');
    if (th) {
      const col = th.dataset.sortCol;
      if (sortState.col === col) {
        if (sortState.dir === 'asc')       sortState.dir = 'desc';
        else if (sortState.dir === 'desc') { sortState.col = null; sortState.dir = null; }
        else                               sortState.dir = 'asc';
      } else {
        sortState.col = col;
        sortState.dir = 'asc';
      }
      applyFilterSortGroup();
      return;
    }

    // Group header collapse/expand
    const groupHeader = e.target.closest('tr.group-header');
    if (groupHeader) {
      const gIdx = groupHeader.dataset.groupIdx;
      const isCollapsed = groupHeader.classList.contains('collapsed');
      groupHeader.classList.toggle('collapsed', !isCollapsed);
      const tbody = groupHeader.closest('tbody');
      if (tbody) {
        tbody.querySelectorAll('[data-group-idx="' + gIdx + '"]').forEach(function(row) {
          row.style.display = isCollapsed ? '' : 'none';
        });
      }
      return;
    }
  });

  resultsContainer.addEventListener('input', function(e) {
    if (e.target.id === 'decode-filter') {
      currentFilter = e.target.value;
      applyFilterSortGroup();
    }
  });

  resultsContainer.addEventListener('change', function(e) {
    if (e.target.id === 'decode-groupby') {
      currentGroupBy = e.target.value;
      applyFilterSortGroup();
    }
  });

  // ── Classify results ──────────────────────────────────────────────────────

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
      // Full value in title attribute; CSS ellipsis handles overflow (Feature 6)
      html += '<td class="col-original" title="' + escapeHtml(r.domain || '') + '">'
            + escapeHtml(r.domain || '') + '</td>';
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

  function escapeHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
})();
