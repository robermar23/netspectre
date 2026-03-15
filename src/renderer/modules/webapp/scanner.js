/**
 * scanner.js — Active Vulnerability Scanner Renderer Module (Feature 7C)
 *
 * Provides:
 *  - Scan configuration panel (target selection, module toggles, concurrency)
 *  - Live findings table (severity-sorted, expandable rows)
 *  - Progress bar + scan summary
 *  - Export (JSON / CSV / HTML)
 *  - "Send to Repeater" integration
 *  - Network workspace badge integration via state.webAppFindings
 */

import { api } from '../../api.js';
import { state } from '../../state.js';
import { SEVERITY_ORDER } from '#shared/webConstants.js';

// ─── Local State ──────────────────────────────────────────────────────────────

let _findings    = [];
let _scanning    = false;
let _tested      = 0;
let _total       = 0;
let _expandedId  = null;
let _activityLog = [];   // capped ring buffer of activity events

/** URLs pre-loaded from sitemap selection; null means use normal sitemap fetch. */
let _preloadedSitemapUrls = null;
const ACTIVITY_MAX = 500;

/** DNS resolution cache: hostname → resolved IPv4 (or null if failed) */
const _dnsCache = new Map();

// ─── DOM Refs ─────────────────────────────────────────────────────────────────

let $startBtn, $stopBtn, $clearBtn, $exportBtn;
let $progressBar, $progressLabel, $summaryLine;
let $findingsTable, $emptyState;
let $concurrencySlider, $concurrencyVal;
let $timeoutInput;
let $moduleCheckboxes;
let $targetModeRadios;
let $urlInput;
let $scanError;
let $sitemapOptions, $multimethodCb;
let $exportDropdown;
let $activityWrap, $activityList, $activityToggleBtn, $activityClearBtn;

// ─── Bootstrap ────────────────────────────────────────────────────────────────

export function init() {
  _bindDomRefs();
  _bindEvents();
  _subscribeIpc();
}

function _bindDomRefs() {
  $startBtn          = document.getElementById('scanner-start-btn');
  $stopBtn           = document.getElementById('scanner-stop-btn');
  $clearBtn          = document.getElementById('scanner-clear-btn');
  $exportBtn         = document.getElementById('scanner-export-btn');
  $progressBar       = document.getElementById('scanner-progress-bar');
  $progressLabel     = document.getElementById('scanner-progress-label');
  $summaryLine       = document.getElementById('scanner-summary-line');
  $findingsTable     = document.getElementById('scanner-findings-body');
  $emptyState        = document.getElementById('scanner-empty-state');
  $concurrencySlider = document.getElementById('scanner-concurrency');
  $concurrencyVal    = document.getElementById('scanner-concurrency-val');
  $timeoutInput      = document.getElementById('scanner-timeout');
  $urlInput          = document.getElementById('scanner-url-input');
  $scanError         = document.getElementById('scanner-error-msg');
  $exportDropdown    = document.getElementById('scanner-export-dropdown');
  $moduleCheckboxes  = document.querySelectorAll('.scanner-module-cb');
  $targetModeRadios  = document.querySelectorAll('input[name="scanner-target-mode"]');
  $sitemapOptions    = document.getElementById('scanner-sitemap-options');
  $multimethodCb     = document.getElementById('scanner-multimethod-cb');
  $activityWrap      = document.getElementById('scanner-activity-wrap');
  $activityList      = document.getElementById('scanner-activity-list');
  $activityToggleBtn = document.getElementById('scanner-activity-toggle');
  $activityClearBtn  = document.getElementById('scanner-activity-clear');
}

function _bindEvents() {
  $startBtn?.addEventListener('click', _startScan);
  $stopBtn?.addEventListener('click', _stopScan);
  $clearBtn?.addEventListener('click', _clearFindings);

  $concurrencySlider?.addEventListener('input', () => {
    if ($concurrencyVal) $concurrencyVal.textContent = $concurrencySlider.value;
  });

  // Show multi-method option only when sitemap source is selected
  $targetModeRadios?.forEach(r => r.addEventListener('change', () => {
    const isSitemap = [...$targetModeRadios].find(x => x.checked)?.value === 'sitemap';
    if ($sitemapOptions) $sitemapOptions.style.display = isSitemap ? 'flex' : 'none';
    if (!isSitemap && $multimethodCb) $multimethodCb.checked = false;
  }));

  // Export dropdown
  $exportBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    $exportDropdown?.classList.toggle('open');
  });
  document.addEventListener('click', () => $exportDropdown?.classList.remove('open'));

  document.getElementById('scanner-export-json')?.addEventListener('click', () => _exportFindings('json'));
  document.getElementById('scanner-export-csv')?.addEventListener('click',  () => _exportFindings('csv'));
  document.getElementById('scanner-export-html')?.addEventListener('click', () => _exportFindings('html'));

  // Activity log toggle / clear
  $activityToggleBtn?.addEventListener('click', () => {
    const collapsed = $activityWrap?.classList.toggle('activity-collapsed');
    if ($activityToggleBtn) $activityToggleBtn.textContent = collapsed ? '▸ Activity Log' : '▾ Activity Log';
  });
  $activityClearBtn?.addEventListener('click', () => {
    _activityLog = [];
    _renderActivityLog();
  });
}

function _subscribeIpc() {
  api.scanner.onFinding(_onFinding);
  api.scanner.onProgress(_onProgress);
  api.scanner.onComplete(_onComplete);
  api.scanner.onError(_onError);
  api.scanner.onActivity(_onActivity);

  // Receive pre-loaded URL lists from the Sitemap panel
  document.addEventListener('scanner:loadFromSitemap', (e) => {
    const urls = e.detail?.urls ?? [];
    if (!urls.length) return;
    _preloadedSitemapUrls = urls;

    // Switch the target mode radio to sitemap
    const sitemapRadio = document.querySelector('input[name="scanner-target-mode"][value="sitemap"]');
    if (sitemapRadio) {
      sitemapRadio.checked = true;
      sitemapRadio.dispatchEvent(new Event('change'));
    }

    // Show a count badge so the user knows what's pre-loaded
    _setSitemapPreloadBadge(urls.length);
  });
}

// ─── Scan Controls ────────────────────────────────────────────────────────────

async function _startScan() {
  if (_scanning) return;
  _hideError();

  const targets = await _buildTargets();
  if (!targets.length) {
    _showError('No targets selected. Choose "Use proxy history" or enter a URL.');
    return;
  }

  const modules = _getSelectedModules();
  if (!modules.length) {
    _showError('Select at least one scan module.');
    return;
  }

  const opts = {
    targets,
    modules,
    concurrency: parseInt($concurrencySlider?.value || '5', 10),
    timeoutMs:   parseInt($timeoutInput?.value || '10000', 10),
  };

  _findings   = [];
  _scanning   = true;
  _tested     = 0;
  _total      = targets.length;

  _renderFindings();
  _setRunning(true);
  _updateProgress(0, targets.length);

  const result = await api.scanner.start(opts);
  if (!result?.success) {
    _showError(result?.error || 'Failed to start scan.');
    _setRunning(false);
    _scanning = false;
  }
}

async function _stopScan() {
  await api.scanner.stop();
  _scanning = false;
  _setRunning(false);
  _setSummary(`Scan stopped. ${_findings.length} finding(s).`);
}

function _clearFindings() {
  _findings    = [];
  _activityLog = [];
  _tested      = 0;
  _total       = 0;
  _expandedId  = null;
  api.scanner.clear();
  _renderFindings();
  _renderActivityLog();
  _updateProgress(0, 0);
  _setSummary('');
}

// ─── IPC Handlers ─────────────────────────────────────────────────────────────

function _onFinding(finding) {
  _findings.push(finding);
  // Sort by severity
  _findings.sort((a, b) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  // Update network workspace badge
  _updateNetworkBadge(finding);
  _renderFindings();
}

function _onProgress({ tested, total }) {
  _tested = tested;
  _total  = total;
  _updateProgress(tested, total);
}

function _onComplete({ findings }) {
  _scanning = false;
  _setRunning(false);
  const counts = _countBySeverity(findings || _findings);
  _setSummary(
    `Scan complete — ${_tested} endpoint(s) tested. ` +
    `${counts.critical ? `${counts.critical} Critical  ` : ''}` +
    `${counts.high     ? `${counts.high} High  ` : ''}` +
    `${counts.medium   ? `${counts.medium} Medium  ` : ''}` +
    `${counts.low      ? `${counts.low} Low  ` : ''}` +
    `${counts.info     ? `${counts.info} Info` : ''}` ||
    'No findings.'
  );
  _updateProgress(_tested, _total, true);
}

function _onError({ message }) {
  _scanning = false;
  _setRunning(false);
  _showError(message);
}

// ─── Target builder ───────────────────────────────────────────────────────────

async function _buildTargets() {
  const mode = [...($targetModeRadios || [])].find(r => r.checked)?.value || 'url';

  if (mode === 'url') {
    const url = $urlInput?.value?.trim();
    if (!url) return [];
    try {
      new URL(url);
      return [{ url, method: 'GET', requestHeaders: {}, body: null }];
    } catch { return []; }
  }

  if (mode === 'history') {
    // Pull from proxy history lightweight summaries already in state
    return (state.proxyHistory || [])
      .filter(r => r.url && r.method)
      .slice(0, 200)
      .map(r => ({
        requestId:       r.id,
        url:             r.url,
        method:          r.method,
        requestHeaders:  r.requestHeaders || {},
        body:            null,  // bodies fetched on demand; headers check is enough
        responseHeaders: r.responseHeaders || {},
      }));
  }

  if (mode === 'sitemap') {
    const multiMethod = $multimethodCb?.checked ?? false;

    // Use pre-loaded selection from sitemap panel if available, otherwise fetch all
    let urls;
    if (_preloadedSitemapUrls) {
      urls = _preloadedSitemapUrls;
      _preloadedSitemapUrls = null;   // consume once
      _setSitemapPreloadBadge(0);
    } else {
      const res = await api.crawler.getSitemap().catch(() => null);
      const sitemap = res?.sitemap || {};
      if (multiMethod) return _expandSitemapTargets(sitemap).slice(0, 400);
      urls = _flattenSitemap(sitemap);
    }

    if (multiMethod) {
      // Re-fetch sitemap to get node metadata for body synthesis
      const res = await api.crawler.getSitemap().catch(() => null);
      const sitemap = res?.sitemap || {};
      return _expandSitemapTargets(sitemap)
        .filter(t => urls.includes(t.url))
        .slice(0, 400);
    }

    return urls.slice(0, 200).map(url => ({
      url,
      method: 'GET',
      requestHeaders: {},
      body: null,
    }));
  }

  return [];
}

function _getSelectedModules() {
  return [...($moduleCheckboxes || [])]
    .filter(cb => cb.checked)
    .map(cb => cb.value);
}

// ─── Rendering ────────────────────────────────────────────────────────────────

function _renderFindings() {
  if (!$findingsTable) return;
  $findingsTable.innerHTML = '';

  if (!_findings.length) {
    if ($emptyState) $emptyState.style.display = 'flex';
    return;
  }
  if ($emptyState) $emptyState.style.display = 'none';

  for (const f of _findings) {
    const row = _buildFindingRow(f);
    $findingsTable.appendChild(row);
  }
}

function _buildFindingRow(f) {
  const wrapper = document.createElement('div');
  wrapper.className = 'scanner-finding-row';
  wrapper.dataset.id = f.id;

  const header = document.createElement('div');
  header.className = 'scanner-finding-header';
  header.innerHTML = `
    <span class="severity-badge severity-${f.severity}">${f.severity.toUpperCase()}</span>
    <span class="scanner-finding-type">${_typeLabel(f.type)}</span>
    <span class="scanner-finding-title">${_esc(f.title)}</span>
    <span class="scanner-finding-url" title="${_esc(f.url)}">${_esc(_shortUrl(f.url))}</span>
    <span class="scanner-finding-param">${_esc(f.parameter || '')}</span>
    <span class="scanner-finding-time">${_formatTime(f.timestamp)}</span>
    <button class="scanner-finding-send-btn" title="Send to Repeater" data-id="${f.id}">↩</button>
    <span class="scanner-finding-chevron">${_expandedId === f.id ? '▲' : '▼'}</span>
  `;

  const detail = document.createElement('div');
  detail.className = 'scanner-finding-detail';
  detail.style.display = _expandedId === f.id ? 'block' : 'none';
  detail.innerHTML = _buildDetailHtml(f);

  header.addEventListener('click', (e) => {
    if (e.target.classList.contains('scanner-finding-send-btn')) return;
    _toggleExpand(f.id);
  });

  header.querySelector('.scanner-finding-send-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    _sendToRepeater(f);
  });

  detail.querySelector('.btn-probe-network')?.addEventListener('click', (e) => {
    e.stopPropagation();
    _probeInNetwork(f);
  });

  wrapper.appendChild(header);
  wrapper.appendChild(detail);
  return wrapper;
}

function _buildDetailHtml(f) {
  const ev = f.evidence || {};
  let hostname = '';
  try { hostname = new URL(f.url).hostname; } catch {}

  return `
    <div class="scanner-detail-grid">
      <div class="scanner-detail-section">
        <div class="scanner-detail-label">Description</div>
        <div class="scanner-detail-value">${_esc(f.description)}</div>
      </div>
      ${f.parameter ? `<div class="scanner-detail-section">
        <div class="scanner-detail-label">Vulnerable Parameter</div>
        <div class="scanner-detail-value scanner-mono">${_esc(f.parameter)}</div>
      </div>` : ''}
      ${f.payload ? `<div class="scanner-detail-section">
        <div class="scanner-detail-label">Payload Used</div>
        <div class="scanner-detail-value scanner-mono">${_esc(f.payload)}</div>
      </div>` : ''}
      <div class="scanner-detail-section">
        <div class="scanner-detail-label">Evidence</div>
        <div class="scanner-detail-value scanner-mono scanner-evidence-box">${_esc(JSON.stringify(ev, null, 2))}</div>
      </div>
      <div class="scanner-detail-section">
        <div class="scanner-detail-label">Remediation</div>
        <div class="scanner-detail-value remediation-text">${_esc(f.remediation)}</div>
      </div>
      ${f.references?.length ? `<div class="scanner-detail-section">
        <div class="scanner-detail-label">References</div>
        <div class="scanner-detail-value">${f.references.map(r => `<span class="ref-chip">${_esc(r)}</span>`).join(' ')}</div>
      </div>` : ''}
      ${hostname ? `<div class="scanner-detail-section scanner-detail-actions">
        <button class="btn-probe-network" data-id="${_esc(f.id)}" title="Resolve ${_esc(hostname)} to IP and add to Network workspace">
          &#127760; Probe in Network
        </button>
      </div>` : ''}
    </div>
  `;
}

function _toggleExpand(id) {
  const prev = _expandedId;
  _expandedId = prev === id ? null : id;

  // Update chevrons and visibility
  for (const row of $findingsTable.querySelectorAll('.scanner-finding-row')) {
    const rowId  = row.dataset.id;
    const detail = row.querySelector('.scanner-finding-detail');
    const chev   = row.querySelector('.scanner-finding-chevron');
    if (detail) detail.style.display = rowId === _expandedId ? 'block' : 'none';
    if (chev)   chev.textContent      = rowId === _expandedId ? '▲' : '▼';
  }
}

// ─── Network badge integration ────────────────────────────────────────────────

/**
 * Async — resolve the finding's hostname to an IP (with caching), then
 * stamp the matching network host card with a web-vuln badge.
 */
async function _updateNetworkBadge(finding) {
  if (!state.webAppFindings) state.webAppFindings = [];
  state.webAppFindings.push(finding);

  let hostname;
  try { hostname = new URL(finding.url).hostname; } catch { return; }
  if (!hostname) return;

  // Resolve hostname → IP (cached)
  let resolvedIp = _dnsCache.get(hostname);
  if (resolvedIp === undefined) {
    try {
      const res = await api.resolveHostname(hostname);
      resolvedIp = res?.success ? res.ip : null;
    } catch {
      resolvedIp = null;
    }
    _dnsCache.set(hostname, resolvedIp);
  }

  // Match against known network hosts by IP or hostname
  const match = (state.hosts || []).find(h =>
    h.ip === resolvedIp || h.ip === hostname || h.hostname === hostname
  );

  if (match) {
    match.hasWebVulns = true;
    const card = document.querySelector(`.host-card[data-ip="${match.ip}"]`);
    if (card && !card.querySelector('.web-vuln-badge')) {
      const badge = document.createElement('span');
      badge.className = 'web-vuln-badge';
      badge.textContent = '⚠ Web Vulns';
      badge.title = 'Web vulnerabilities found by active scanner';
      card.querySelector('.host-meta')?.appendChild(badge);
    }
  }
}

/**
 * Resolve finding hostname → IP, inject as a new host into the network
 * workspace, then switch to the network tab.
 */
async function _probeInNetwork(finding) {
  let hostname;
  try { hostname = new URL(finding.url).hostname; } catch { return; }
  if (!hostname) return;

  // Resolve IP (use cache if available)
  let ip = _dnsCache.get(hostname);
  if (ip === undefined) {
    try {
      const res = await api.resolveHostname(hostname);
      ip = res?.success ? res.ip : null;
    } catch { ip = null; }
    _dnsCache.set(hostname, ip);
  }

  if (!ip) {
    // hostname is already an IP, or DNS failed — try hostname as IP directly
    ip = hostname;
  }

  // Avoid duplicating an existing host entry
  const existing = (state.hosts || []).find(h => h.ip === ip);
  if (!existing) {
    const newHost = {
      ip,
      hostname,
      source: 'webapp-scanner',
      ports: [],
      hasWebVulns: true,
    };
    if (!state.hosts) state.hosts = [];
    state.hosts.push(newHost);
    // Notify network workspace to re-render its host list
    window.dispatchEvent(new CustomEvent('network:hostAdded', { detail: newHost }));
  } else {
    existing.hasWebVulns = true;
  }

  // Switch to the Network workspace tab
  const networkTab = document.querySelector('.workspace-tab[data-workspace="network"]');
  networkTab?.click();
}

// ─── Repeater integration ─────────────────────────────────────────────────────

function _sendToRepeater(finding) {
  // Reconstruct a raw HTTP request from the finding's available data
  const parsed    = (() => { try { return new URL(finding.url); } catch { return null; } })();
  const method    = finding.method ?? 'GET';
  const pathQuery = parsed ? (parsed.pathname + parsed.search) : (finding.url ?? '/');
  const host      = parsed ? parsed.host : '';
  const raw       = `${method} ${pathQuery} HTTP/1.1\r\nHost: ${host}\r\n\r\n`;
  const label     = finding.title ? `${finding.title.slice(0, 30)} — Scanner` : 'Scanner Finding';

  document.dispatchEvent(new CustomEvent('repeater:sendTo', {
    detail: { raw, url: finding.url ?? '', label },
  }));
}

// ─── Export ───────────────────────────────────────────────────────────────────

async function _exportFindings(format) {
  $exportDropdown?.classList.remove('open');
  if (!_findings.length) return;
  const result = await api.scanner.export(format, _findings);
  if (!result?.success) return;

  const ext   = format === 'html' ? 'html' : format === 'csv' ? 'csv' : 'json';
  const mime  = format === 'html' ? 'text/html' : format === 'csv' ? 'text/csv' : 'application/json';
  const blob  = new Blob([result.content], { type: mime });
  const url   = URL.createObjectURL(blob);
  const a     = document.createElement('a');
  a.href      = url;
  a.download  = `netspecter-scan-${Date.now()}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Activity Log ─────────────────────────────────────────────────────────────

function _onActivity(ev) {
  _activityLog.push(ev);
  if (_activityLog.length > ACTIVITY_MAX) _activityLog.shift();
  _appendActivityEntry(ev);
  // Expand the log automatically when the scan starts
  if (ev.status === 'start' && $activityWrap?.classList.contains('activity-collapsed')) {
    $activityWrap.classList.remove('activity-collapsed');
    if ($activityToggleBtn) $activityToggleBtn.textContent = '▾ Activity Log';
  }
}

function _appendActivityEntry(ev) {
  if (!$activityList) return;
  const isDone = ev.status === 'done';
  const entry  = document.createElement('div');
  entry.className = `activity-entry activity-${isDone ? 'done' : 'start'}`;

  const shortUrl = (() => {
    try {
      const u = new URL(ev.url);
      return u.hostname + (u.pathname.length > 35 ? u.pathname.slice(0, 35) + '…' : u.pathname);
    } catch { return ev.url; }
  })();

  entry.innerHTML = `
    <span class="activity-ts">${new Date(ev.timestamp).toLocaleTimeString()}</span>
    <span class="activity-status-icon">${isDone ? '✓' : '→'}</span>
    <span class="activity-method">${_esc(ev.method)}</span>
    <span class="activity-module-chip activity-chip-${_esc(ev.module)}">${_esc(ev.moduleLabel)}</span>
    <span class="activity-url" title="${_esc(ev.url)}">${_esc(shortUrl)}</span>
    ${isDone && ev.findings > 0
      ? `<span class="activity-hit">⚠ ${ev.findings} finding${ev.findings > 1 ? 's' : ''}</span>`
      : ''}
    <span class="activity-desc" title="${_esc(ev.description)}">${isDone ? '' : _esc(ev.description)}</span>
  `;
  $activityList.appendChild(entry);
  // Auto-scroll to bottom
  $activityList.scrollTop = $activityList.scrollHeight;
}

function _renderActivityLog() {
  if (!$activityList) return;
  $activityList.innerHTML = '';
  for (const ev of _activityLog) _appendActivityEntry(ev);
}

// ─── UI helpers ───────────────────────────────────────────────────────────────

function _setRunning(running) {
  if ($startBtn) $startBtn.disabled = running;
  if ($stopBtn)  $stopBtn.disabled  = !running;
  if ($clearBtn) $clearBtn.disabled = running;
}

function _updateProgress(tested, total, done = false) {
  const pct = total > 0 ? Math.round((tested / total) * 100) : 0;
  if ($progressBar)  $progressBar.style.width = `${pct}%`;
  if ($progressBar)  $progressBar.classList.toggle('done', done);
  if ($progressLabel) $progressLabel.textContent = total > 0
    ? `${tested} / ${total} endpoints tested (${pct}%)`
    : '';
}

function _setSummary(text) {
  if ($summaryLine) $summaryLine.textContent = text;
}

function _showError(msg) {
  if ($scanError) { $scanError.textContent = msg; $scanError.style.display = 'block'; }
}

/** Show or clear a count badge on the sitemap radio label when URLs are pre-loaded. */
function _setSitemapPreloadBadge(count) {
  // Find or create the badge span next to the sitemap radio label
  const sitemapLabel = document.querySelector('label.scanner-radio-label:has(input[value="sitemap"])');
  if (!sitemapLabel) return;
  let badge = sitemapLabel.querySelector('.scanner-preload-badge');
  if (count > 0) {
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'scanner-preload-badge';
      sitemapLabel.appendChild(badge);
    }
    badge.textContent = `${count} URLs`;
  } else {
    badge?.remove();
  }
}

function _hideError() {
  if ($scanError) $scanError.style.display = 'none';
}

function _countBySeverity(findings) {
  return findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
}

function _typeLabel(type) {
  return {
    sqli:          'SQLi',
    xss:           'XSS',
    ssrf:          'SSRF',
    xxe:           'XXE',
    cmdInjection:  'CMDi',
    pathTraversal: 'LFI',
    cors:          'CORS',
    headers:       'Headers',
    brokenAuth:    'Auth',
    deserialize:   'Deserial.',
  }[type] || type;
}

function _shortUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname.length > 40 ? u.pathname.slice(0, 40) + '…' : u.pathname);
  } catch { return url; }
}

function _formatTime(ts) {
  return new Date(ts).toLocaleTimeString();
}

function _esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Flatten the sitemap tree { [host]: { [path]: { children, methods } } }
 * into a flat array of full URLs.
 */
function _flattenSitemap(sitemap) {
  const urls = [];
  for (const [host, rootNode] of Object.entries(sitemap || {})) {
    // Include the root path itself
    urls.push(`https://${host}/`);
    // rootNode has shape { methods, forms, params, statusCode, children: { [seg]: node } }
    // Walk only the children map so path segments are iterated, not node properties
    _walkNode(host, '', rootNode.children || {}, urls);
  }
  return [...new Set(urls)];
}

function _walkNode(host, prefix, children, acc) {
  if (!children || typeof children !== 'object') return;
  for (const [seg, child] of Object.entries(children)) {
    const path = prefix + '/' + seg;
    acc.push(`https://${host}${path}`);
    if (child && child.children) _walkNode(host, path, child.children, acc);
  }
}

/**
 * Walk the sitemap tree and produce one target per (url × method) combination.
 * For mutating methods (POST/PUT/PATCH), synthesize a body from discovered
 * form inputs or query params — values are left empty/placeholder so the
 * scanner probes structure rather than submitting real data.
 */
function _expandSitemapTargets(sitemap) {
  const targets = [];
  for (const [host, rootNode] of Object.entries(sitemap || {})) {
    _walkNodeExpand(host, '/', rootNode, targets);
    _walkChildrenExpand(host, '', rootNode.children || {}, targets);
  }
  return targets;
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function _walkChildrenExpand(host, prefix, children, acc) {
  for (const [seg, node] of Object.entries(children || {})) {
    const path = prefix + '/' + seg;
    _walkNodeExpand(host, path, node, acc);
    _walkChildrenExpand(host, path, node.children || {}, acc);
  }
}

function _walkNodeExpand(host, path, node, acc) {
  const url     = `https://${host}${path}`;
  const methods = (node.methods?.length ? node.methods : ['GET']).map(m => m.toUpperCase());

  // Always include GET
  if (!methods.includes('GET')) methods.unshift('GET');

  for (const method of methods) {
    if (MUTATING_METHODS.has(method)) {
      // Build a synthetic body from the node's forms or params
      const body    = _synthesizeBody(node, method);
      const ct      = body.contentType;
      acc.push({
        url,
        method,
        requestHeaders: ct ? { 'content-type': ct } : {},
        body: body.data || null,
      });
    } else {
      acc.push({ url, method, requestHeaders: {}, body: null });
    }
  }
}

/**
 * Build a synthetic request body for a mutating method.
 * Prefers a matching HTML form; falls back to sitemap params; falls back to empty.
 * Returns { data: string|null, contentType: string|null }.
 */
function _synthesizeBody(node, method) {
  // Try to find a form whose method matches
  const forms = node.forms || [];
  const matchingForm = forms.find(f => f.method === method) || forms[0];

  if (matchingForm?.inputs?.length) {
    const p = new URLSearchParams();
    for (const input of matchingForm.inputs) {
      p.set(input.name, input.value || '');
    }
    return { data: p.toString(), contentType: 'application/x-www-form-urlencoded' };
  }

  // Fall back to query params recorded for this node
  const params = node.params || [];
  if (params.length) {
    const p = new URLSearchParams();
    for (const param of params) p.set(param.name, '');
    return { data: p.toString(), contentType: 'application/x-www-form-urlencoded' };
  }

  // Nothing known — send an empty JSON object so modules can still probe headers/CORS/auth
  if (method !== 'DELETE') {
    return { data: '{}', contentType: 'application/json' };
  }
  return { data: null, contentType: null };
}

// ─── Public: pre-fill from Network workspace ──────────────────────────────────

export function scanUrl(url) {
  if ($urlInput) $urlInput.value = url;
  // Switch to URL target mode
  const urlRadio = document.querySelector('input[name="scanner-target-mode"][value="url"]');
  if (urlRadio) urlRadio.checked = true;
}
