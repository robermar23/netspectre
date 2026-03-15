/**
 * sitemap.js — Site Map Renderer Module (Feature 7B)
 *
 * Renders the sitemap tree view, manages the active-crawl UI, and integrates
 * API schema detection results.  All state is maintained in this module;
 * the authoritative sitemap lives in the main process (crawler.js).
 */

import { api } from '../../api.js';
import { state } from '../../state.js';
import { openPanel as openDirFuzzPanel } from '../dirFuzz.js';

// ─── Local State ──────────────────────────────────────────────────────────────

/** Local mirror of the sitemap tree: { [hostname]: SitemapNode } */
let _sitemap    = {};
let _stats      = { hosts: 0, urls: 0, forms: 0, params: 0 };
let _crawling   = false;
let _selectedNode = null;  // { url, node }
let _contextTarget = null; // URL string for context menu

/** Deduplication set — avoids double-counting repeated URL events. */
const _seenUrls = new Set();

/** DNS resolution cache: hostname → resolved IPv4 (or null if failed) */
const _dnsCache = new Map();

/** Pending render timer — coalesces rapid URL events into one DOM rebuild. */
let _renderTimer = null;

// Discovered API schemas keyed by schemaUrl
const _apiSchemas = new Map();

// ─── DOM Refs (populated in init) ─────────────────────────────────────────────

let $treeContainer;
let $statsHosts, $statsUrls, $statsForms;
let $progressWrap, $progressBar, $progressLabel;
let $startBtn, $stopBtn;
let $targetInput;
let $detailEmpty, $detailContent, $detailUrl, $detailMethods;
let $detailParamsList, $detailFormsList;
let $contextMenu;
let $apiPanel, $apiContent;
let $playwrightBanner;
let $proxyNotice;
let $crawlError, $crawlErrorText;
let $crawlModal;

// ─── Bootstrap ────────────────────────────────────────────────────────────────

export function init() {
  _bindDomRefs();
  _bindEvents();
  _subscribeIpc();
  _loadSitemapSnapshot();
}

function _bindDomRefs() {
  $treeContainer   = document.getElementById('sitemap-tree-container');
  // Move context menu to <body> immediately so backdrop-filter on ancestor
  // panels doesn't break position:fixed viewport-relative coordinates.
  const menuEl = document.getElementById('sitemap-context-menu');
  if (menuEl && menuEl.parentElement !== document.body) {
    document.body.appendChild(menuEl);
  }
  $statsHosts      = document.getElementById('sitemap-stat-hosts');
  $statsUrls       = document.getElementById('sitemap-stat-urls');
  $statsForms      = document.getElementById('sitemap-stat-forms');
  $progressWrap    = document.getElementById('sitemap-progress-wrap');
  $progressBar     = document.getElementById('sitemap-progress-bar');
  $progressLabel   = document.getElementById('sitemap-progress-label');
  $startBtn        = document.getElementById('btn-sitemap-crawl-start');
  $stopBtn         = document.getElementById('btn-sitemap-crawl-stop');
  $targetInput     = document.getElementById('sitemap-target-input');
  $detailEmpty     = document.getElementById('sitemap-detail-empty');
  $detailContent   = document.getElementById('sitemap-detail-content');
  $detailUrl       = document.getElementById('sitemap-detail-url');
  $detailMethods   = document.getElementById('sitemap-detail-methods');
  $detailParamsList= document.getElementById('sitemap-detail-params-list');
  $detailFormsList = document.getElementById('sitemap-detail-forms-list');
  $contextMenu     = document.getElementById('sitemap-context-menu');

  // Inject "Probe in Network" item into the sitemap context menu
  if ($contextMenu) {
    const probeItem = document.createElement('div');
    probeItem.className = 'context-menu-item';
    probeItem.dataset.action = 'probe-network';
    probeItem.textContent = '🌐 Probe in Network';
    $contextMenu.appendChild(probeItem);
  }

  $apiPanel        = document.getElementById('sitemap-api-panel');
  $apiContent      = document.getElementById('sitemap-api-content');
  $playwrightBanner= document.getElementById('sitemap-playwright-missing');
  $proxyNotice     = document.getElementById('sitemap-proxy-notice');
  $crawlError      = document.getElementById('sitemap-crawl-error');
  $crawlErrorText  = document.getElementById('sitemap-crawl-error-text');
  $crawlModal      = document.getElementById('sitemap-crawl-modal');
}

function _bindEvents() {
  // ── Start / Stop Crawl ───────────────────────────────────────────────────────
  $startBtn?.addEventListener('click', () => {
    const target = $targetInput?.value.trim();
    if (!target) { _showTargetError(); return; }
    // Open config modal
    document.getElementById('crawl-start-url').value = target;
    _showModal($crawlModal);
  });

  $stopBtn?.addEventListener('click', () => api.crawler.stop());

  document.getElementById('btn-crawl-modal-cancel')?.addEventListener('click', () => _hideModal($crawlModal));
  document.getElementById('btn-sitemap-crawl-modal-close')?.addEventListener('click', () => _hideModal($crawlModal));

  document.getElementById('btn-crawl-modal-start')?.addEventListener('click', async () => {
    _hideModal($crawlModal);
    await _startCrawl();
  });

  // ── API Detection ────────────────────────────────────────────────────────────
  document.getElementById('btn-sitemap-api-detect')?.addEventListener('click', async () => {
    const target = $targetInput?.value.trim() || _firstHost();
    if (!target) { _showTargetError(); return; }

    const btn = document.getElementById('btn-sitemap-api-detect');
    if (btn) { btn.textContent = 'Probing…'; btn.disabled = true; }

    await api.crawler.detectApis(target);
    // Button is re-enabled by the onApiDetectComplete subscriber below
  });

  document.getElementById('btn-sitemap-api-close')?.addEventListener('click', () => {
    if ($apiPanel) $apiPanel.style.display = 'none';
  });

  // ── Export / Clear ───────────────────────────────────────────────────────────
  document.getElementById('btn-sitemap-export')?.addEventListener('click', async () => {
    const res = await api.crawler.exportSitemap();
    if (res.success) {
      const blob = new Blob([res.json], { type: 'application/json' });
      const a    = document.createElement('a');
      a.href     = URL.createObjectURL(blob);
      a.download = `sitemap-${Date.now()}.json`;
      a.click();
    }
  });

  document.getElementById('btn-sitemap-clear')?.addEventListener('click', async () => {
    await api.crawler.clearSitemap();
    _sitemap = {};
    _stats   = { hosts: 0, urls: 0, forms: 0, params: 0 };
    _seenUrls.clear();
    if (_renderTimer) { clearTimeout(_renderTimer); _renderTimer = null; }
    _apiSchemas.clear();
    _renderTree();
    _updateStats();
    if ($apiPanel) $apiPanel.style.display = 'none';
  });

  // ── Tree expand / collapse all ───────────────────────────────────────────────
  document.getElementById('btn-sitemap-expand-all')?.addEventListener('click',   () => _toggleAllNodes(true));
  document.getElementById('btn-sitemap-collapse-all')?.addEventListener('click', () => _toggleAllNodes(false));

  // ── Install Playwright ───────────────────────────────────────────────────────
  document.getElementById('btn-sitemap-install-playwright')?.addEventListener('click', () => {
    // Instruct user — actual install requires terminal access
    alert('Run the following in your terminal:\n\nnpm install playwright-core\nnpx playwright install chromium');
  });

  // ── Dismiss error banner ─────────────────────────────────────────────────────
  document.getElementById('btn-sitemap-dismiss-error')?.addEventListener('click', () => {
    if ($crawlError) $crawlError.style.display = 'none';
  });

  // ── Context Menu ─────────────────────────────────────────────────────────────
  $contextMenu?.querySelectorAll('.context-menu-item').forEach(btn => {
    btn.addEventListener('click', () => {
      _handleContextAction(btn.dataset.action, _contextTarget);
      _hideContextMenu();
    });
  });

  // Hide context menu on outside click
  document.addEventListener('click', (e) => {
    if (!$contextMenu?.contains(e.target)) _hideContextMenu();
  });

  // ── Detail Panel Tabs ────────────────────────────────────────────────────────
  document.querySelectorAll('.sitemap-detail-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.sitemap-detail-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.dataset.tab;
      document.querySelectorAll('.sitemap-detail-tab-pane').forEach(p => {
        p.style.display = p.id === `sitemap-detail-tab-${tab}` ? '' : 'none';
      });
    });
  });

  // ── Detail Action Buttons ─────────────────────────────────────────────────
  const _detailAction = (action) => () => {
    if (_selectedNode) _handleContextAction(action, _selectedNode.url);
  };
  document.getElementById('btn-sitemap-send-repeater') ?.addEventListener('click', _detailAction('send-repeater'));
  document.getElementById('btn-sitemap-send-intruder') ?.addEventListener('click', _detailAction('send-intruder'));
  document.getElementById('btn-sitemap-send-dirfuzzer')?.addEventListener('click', _detailAction('send-dirfuzzer'));
  document.getElementById('btn-sitemap-open-browser')  ?.addEventListener('click', _detailAction('open-browser'));
  document.getElementById('btn-sitemap-probe-network') ?.addEventListener('click', _detailAction('probe-network'));
  document.getElementById('btn-sitemap-api-detect-url')?.addEventListener('click', _detailAction('api-detect'));
}

function _scheduleRender() {
  if (_renderTimer) return; // already pending
  _renderTimer = setTimeout(() => {
    _renderTimer = null;
    _renderTree();
    _updateStats();
  }, 150);
}

function _subscribeIpc() {
  api.crawler.onUrlFound((data) => {
    _addUrlToTree(data.url);
    _scheduleRender();
  });

  api.crawler.onFormFound((data) => {
    _addFormToTree(data.form);
    _scheduleRender();
  });

  api.crawler.onProgress((progress) => {
    _setCrawlProgress(progress);
  });

  api.crawler.onComplete(() => {
    _crawling = false;
    _updateCrawlButtons();
    if ($progressWrap) $progressWrap.style.display = 'none';
    if ($proxyNotice) $proxyNotice.style.display = 'none';
    // Flush any pending debounced render before the crawl is considered done
    _flushRender();
  });

  api.crawler.onError((err) => {
    _crawling = false;
    _updateCrawlButtons();
    if ($progressWrap) $progressWrap.style.display = 'none';
    if ($proxyNotice) $proxyNotice.style.display = 'none';
    _flushRender();
    _showCrawlError(err.message ?? 'Unknown crawl error');
  });

  api.crawler.onDependencyMissing(() => {
    _crawling = false;
    _updateCrawlButtons();
    if ($playwrightBanner) $playwrightBanner.style.display = 'flex';
  });

  api.crawler.onApiDetectComplete(({ found }) => {
    const btn = document.getElementById('btn-sitemap-api-detect');
    if (btn) { btn.textContent = 'Detect APIs'; btn.disabled = false; }

    if (found === 0) {
      _showCrawlError('No API schemas found. The target may not expose OpenAPI or GraphQL endpoints at standard paths.');
    }
  });

  api.crawler.onApiSchemaFound((schema) => {
    _apiSchemas.set(schema.schemaUrl, schema);
    _renderApiSchemas();
    if ($apiPanel) $apiPanel.style.display = 'flex';
    // Add schema endpoints to sitemap
    for (const ep of schema.endpoints ?? []) {
      _addUrlToTree(ep.path.startsWith('http') ? ep.path : schema.schemaUrl);
    }
    _renderTree();
    _updateStats();
  });
}

// ─── Network Workspace Pivot ──────────────────────────────────────────────────

/**
 * Resolve the hostname in `url` to an IPv4 address, inject it into the network
 * workspace host list, and switch to the Network tab.
 */
async function _probeHostInNetwork(url) {
  if (!url) return;
  let hostname;
  try { hostname = new URL(url).hostname; } catch { return; }

  let ip = _dnsCache.get(hostname);
  if (ip === undefined) {
    try {
      const res = await api.resolveHostname(hostname);
      ip = res?.success ? res.ip : null;
    } catch { ip = null; }
    _dnsCache.set(hostname, ip);
  }

  const resolvedIp = ip || hostname;

  const existing = (state.hosts || []).find(h => h.ip === resolvedIp);
  if (!existing) {
    const newHost = {
      ip:       resolvedIp,
      hostname: resolvedIp !== hostname ? hostname : null,
      source:   'sitemap',
      ports:    [],
    };
    if (!state.hosts) state.hosts = [];
    state.hosts.push(newHost);
    window.dispatchEvent(new CustomEvent('network:hostAdded', { detail: newHost }));
  }

  document.querySelector('.workspace-tab[data-workspace="network"]')?.click();
}

// ─── Crawl Lifecycle ──────────────────────────────────────────────────────────

async function _startCrawl() {
  const startUrl        = document.getElementById('crawl-start-url')?.value.trim();
  const maxDepth        = parseInt(document.getElementById('crawl-max-depth')?.value ?? '3', 10);
  const maxPages        = parseInt(document.getElementById('crawl-max-pages')?.value ?? '200', 10);
  const includeSubdomains = document.getElementById('crawl-include-subdomains')?.checked ?? false;
  const submitForms     = document.getElementById('crawl-submit-forms')?.checked ?? true;
  const clickButtons    = document.getElementById('crawl-click-buttons')?.checked ?? true;
  const respectRobots   = document.getElementById('crawl-respect-robots')?.checked ?? true;

  if (!startUrl) return;

  const res = await api.crawler.start({
    startUrl,
    maxDepth:           Math.min(maxDepth, 10),
    maxPages:           Math.min(maxPages, 5000),
    includeSubdomains,
    submitForms,
    clickButtons,
    respectRobots,
    waitForNetworkIdle: true,
  });

  if (res.success) {
    _crawling = true;
    _updateCrawlButtons();
    if ($progressWrap) {
      $progressWrap.style.display = 'flex';
      $progressBar.style.width = '0%';
      $progressLabel.textContent = 'Starting…';
    }
    if ($playwrightBanner) $playwrightBanner.style.display = 'none';
    if ($crawlError) $crawlError.style.display = 'none';

    // Warn when proxy isn't running — crawl still works but goes direct
    try {
      const status = await api.proxy.getStatus();
      if ($proxyNotice) $proxyNotice.style.display = status.running ? 'none' : 'flex';
    } catch { if ($proxyNotice) $proxyNotice.style.display = 'none'; }
  } else if (res.error) {
    _showCrawlError(res.error);
  }
}

function _setCrawlProgress({ visited, queued, total }) {
  if (!$progressBar || !$progressLabel) return;
  const pct = total > 0 ? Math.round((visited / total) * 100) : 0;
  $progressBar.style.width = `${pct}%`;
  $progressLabel.textContent = `Visited ${visited} / ${total} — ${queued} queued`;
}

function _updateCrawlButtons() {
  if ($startBtn) $startBtn.style.display = _crawling ? 'none' : '';
  if ($stopBtn)  $stopBtn.style.display  = _crawling ? '' : 'none';
}

// ─── Tree Management ──────────────────────────────────────────────────────────

function _addUrlToTree(rawUrl) {
  if (!rawUrl) return;
  let u;
  try { u = new URL(rawUrl); } catch { return; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return;

  const host = u.hostname;
  if (!_sitemap[host]) {
    _sitemap[host] = { methods: [], forms: [], params: [], children: {}, statusCode: null };
  }

  const segments = u.pathname.replace(/^\//, '').split('/').filter(Boolean);
  let node = _sitemap[host];
  for (const seg of segments) {
    if (!node.children[seg]) {
      node.children[seg] = { methods: [], forms: [], params: [], children: {}, statusCode: null };
    }
    node = node.children[seg];
  }

  // Only count each unique URL once regardless of how many times it's reported.
  if (!_seenUrls.has(rawUrl)) {
    _seenUrls.add(rawUrl);
    _stats.urls++;
  }
  _stats.hosts = Object.keys(_sitemap).length;

  // Store query parameters on the leaf node (deduplicated by name+source).
  for (const [name] of u.searchParams.entries()) {
    if (!node.params.some(p => p.name === name && p.source === 'query')) {
      node.params.push({ name, source: 'query' });
      _stats.params++;
    }
  }
}

function _addFormToTree(form) {
  if (!form?.action) return;
  // Ensure the action URL exists as a tree node.
  _addUrlToTree(form.action);

  // Walk to the node for the form's action and store the form object there.
  let u;
  try { u = new URL(form.action); } catch { return; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return;

  const host = u.hostname;
  if (!_sitemap[host]) return;

  const segments = u.pathname.replace(/^\//, '').split('/').filter(Boolean);
  let node = _sitemap[host];
  for (const seg of segments) {
    if (!node.children[seg]) return;
    node = node.children[seg];
  }

  // Deduplicate by method+action key.
  const key = `${(form.method ?? 'GET').toUpperCase()}:${form.action}`;
  if (!node.forms.some(f => `${(f.method ?? 'GET').toUpperCase()}:${f.action}` === key)) {
    node.forms.push(form);
    _stats.forms++;
  }
}

// ─── Tree Rendering ───────────────────────────────────────────────────────────

function _renderTree() {
  if (!$treeContainer) return;

  if (Object.keys(_sitemap).length === 0) {
    $treeContainer.innerHTML = `
      <div class="sitemap-empty-state">
        <span class="sitemap-empty-icon">🗺️</span>
        <p>No URLs discovered yet.</p>
        <p class="sitemap-empty-hint">Start the proxy and browse a target,<br>or use Active Crawl.</p>
      </div>`;
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const [hostname, rootNode] of Object.entries(_sitemap)) {
    fragment.appendChild(_buildHostNode(hostname, rootNode));
  }

  $treeContainer.innerHTML = '';
  $treeContainer.appendChild(fragment);
}

function _buildHostNode(hostname, rootNode) {
  const wrapper = document.createElement('div');
  wrapper.className = 'sitemap-host-group';

  const header = document.createElement('div');
  header.className = 'sitemap-host-header';
  header.innerHTML = `
    <span class="sitemap-expand-icon">▾</span>
    <span class="sitemap-host-icon">🌐</span>
    <span class="sitemap-host-name">${_esc(hostname)}</span>
    <span class="sitemap-badge">${_countChildren(rootNode)} URLs</span>`;

  header.addEventListener('click', () => _toggleGroup(childrenDiv, header.querySelector('.sitemap-expand-icon')));
  header.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    _showContextMenu(e, `https://${hostname}`);
  });

  const childrenDiv = document.createElement('div');
  childrenDiv.className = 'sitemap-children';

  // Render root-level children
  for (const [seg, child] of Object.entries(rootNode.children)) {
    childrenDiv.appendChild(_buildPathNode(`https://${hostname}`, seg, child, 1));
  }
  // Also show root path itself
  if (rootNode.methods.length > 0 || rootNode.forms.length > 0) {
    const rootEntry = _buildPathEntry(`https://${hostname}/`, '/', rootNode);
    childrenDiv.prepend(rootEntry);
  }

  wrapper.appendChild(header);
  wrapper.appendChild(childrenDiv);
  return wrapper;
}

const _API_SEGMENTS = new Set(['api', 'v1', 'v2', 'v3', 'v4', 'v5', 'graphql', 'rest', 'rpc', 'gql', 'swagger', 'openapi']);

function _buildPathNode(parentUrl, segment, node, depth) {
  const url     = `${parentUrl}/${segment}`;
  const hasKids = Object.keys(node.children).length > 0;
  const isApi   = _API_SEGMENTS.has(segment.toLowerCase());
  const wrapper = document.createElement('div');
  wrapper.className = 'sitemap-path-node';
  wrapper.style.paddingLeft = `${depth * 16}px`;

  const row = document.createElement('div');
  row.className = `sitemap-path-row ${_nodeColorClass(node)}`;
  row.setAttribute('data-url', url);

  row.innerHTML = `
    ${hasKids ? `<span class="sitemap-expand-icon sitemap-expandable">▾</span>` : `<span class="sitemap-expand-icon">  </span>`}
    <span class="sitemap-path-segment">${_esc(segment)}</span>
    ${node.methods.map(m => `<span class="sitemap-method-badge method-${m.toLowerCase()}">${_esc(m)}</span>`).join('')}
    ${isApi ? `<span class="sitemap-badge badge-api">API</span>` : ''}
    ${node.forms.length  > 0 ? `<span class="sitemap-badge badge-forms">${node.forms.length} form${node.forms.length > 1 ? 's' : ''}</span>` : ''}
    ${node.params.length > 0 ? `<span class="sitemap-badge badge-params">${node.params.length} param${node.params.length > 1 ? 's' : ''}</span>` : ''}`;

  row.addEventListener('click', (e) => {
    if ((e.target).classList.contains('sitemap-expandable')) {
      _toggleGroup(childrenDiv, row.querySelector('.sitemap-expandable'));
    } else {
      _selectNode(url, node);
    }
  });

  row.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    _showContextMenu(e, url);
  });

  wrapper.appendChild(row);

  const childrenDiv = document.createElement('div');
  childrenDiv.className = 'sitemap-children';
  if (hasKids) {
    for (const [childSeg, childNode] of Object.entries(node.children)) {
      childrenDiv.appendChild(_buildPathNode(url, childSeg, childNode, depth + 1));
    }
  }
  wrapper.appendChild(childrenDiv);

  return wrapper;
}

function _buildPathEntry(url, label, node) {
  const row = document.createElement('div');
  row.className = `sitemap-path-row ${_nodeColorClass(node)} sitemap-root-entry`;
  row.setAttribute('data-url', url);
  row.innerHTML = `
    <span class="sitemap-expand-icon"> </span>
    <span class="sitemap-path-segment">${_esc(label)}</span>
    ${node.methods.map(m => `<span class="sitemap-method-badge method-${m.toLowerCase()}">${_esc(m)}</span>`).join('')}`;
  row.addEventListener('click', () => _selectNode(url, node));
  row.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    _showContextMenu(e, url);
  });
  return row;
}

function _nodeColorClass(node) {
  if (node.flagged) return 'node-danger';
  if (node.forms.length > 0 || node.params.length > 0) return 'node-warning';
  return 'node-normal';
}

function _countChildren(node) {
  let count = 1;
  for (const child of Object.values(node.children)) count += _countChildren(child);
  return count;
}

function _toggleGroup(childrenDiv, icon) {
  const collapsed = childrenDiv.classList.toggle('collapsed');
  if (icon) icon.textContent = collapsed ? '▸' : '▾';
}

function _toggleAllNodes(expand) {
  document.querySelectorAll('.sitemap-children').forEach(el => {
    el.classList.toggle('collapsed', !expand);
  });
  document.querySelectorAll('.sitemap-expandable').forEach(el => {
    el.textContent = expand ? '▾' : '▸';
  });
}

// ─── Node Selection & Detail Panel ───────────────────────────────────────────

function _selectNode(url, node) {
  _selectedNode = { url, node };

  // Highlight selected row
  document.querySelectorAll('.sitemap-path-row.selected').forEach(r => r.classList.remove('selected'));
  document.querySelector(`.sitemap-path-row[data-url="${CSS.escape(url)}"]`)?.classList.add('selected');

  if ($detailEmpty)   $detailEmpty.style.display   = 'none';
  if ($detailContent) $detailContent.style.display = 'flex';

  if ($detailUrl) {
    $detailUrl.textContent = url;
    $detailUrl.title       = url;
  }

  if ($detailMethods) {
    $detailMethods.innerHTML = (node.methods ?? [])
      .map(m => `<span class="sitemap-method-badge method-${m.toLowerCase()}">${_esc(m)}</span>`)
      .join('');
  }

  // Params tab
  if ($detailParamsList) {
    if (node.params?.length > 0) {
      $detailParamsList.innerHTML = `
        <table class="sitemap-params-table">
          <thead><tr><th>Name</th><th>Source</th></tr></thead>
          <tbody>${node.params.map(p => `<tr><td>${_esc(p.name)}</td><td>${_esc(p.source)}</td></tr>`).join('')}</tbody>
        </table>`;
    } else {
      $detailParamsList.innerHTML = '<span class="sitemap-empty-hint">No parameters found</span>';
    }
  }

  // Forms tab
  if ($detailFormsList) {
    if (node.forms?.length > 0) {
      $detailFormsList.innerHTML = node.forms.map((form, i) => `
        <div class="sitemap-form-card">
          <div class="sitemap-form-header">
            <span class="sitemap-method-badge method-${form.method?.toLowerCase()}">${_esc(form.method ?? 'GET')}</span>
            <span class="sitemap-form-action">${_esc(form.action ?? '')}</span>
          </div>
          <div class="sitemap-form-inputs">
            ${(form.inputs ?? []).map(inp => `
              <span class="sitemap-input-pill">${_esc(inp.name)} <em>${_esc(inp.type)}</em></span>`).join('')}
          </div>
        </div>`).join('');
    } else {
      $detailFormsList.innerHTML = '<span class="sitemap-empty-hint">No forms found</span>';
    }
  }
}

// ─── API Schema Panel ─────────────────────────────────────────────────────────

function _renderApiSchemas() {
  if (!$apiContent || _apiSchemas.size === 0) return;

  $apiContent.innerHTML = '';
  for (const schema of _apiSchemas.values()) {
    const card = document.createElement('div');
    card.className = `sitemap-api-card sitemap-api-${schema.type}`;
    card.innerHTML = `
      <div class="sitemap-api-card-header">
        <span class="sitemap-api-type-badge">${_esc(schema.type.toUpperCase())}</span>
        <strong>${_esc(schema.title)}</strong>
        ${schema.version ? `<span class="sitemap-api-version">v${_esc(schema.version)}</span>` : ''}
        <span class="sitemap-badge">${schema.endpoints.length} endpoints</span>
        <span class="sitemap-api-url">${_esc(schema.schemaUrl)}</span>
      </div>
      <div class="sitemap-api-endpoints">
        ${schema.endpoints.slice(0, 50).map(ep => `
          <div class="sitemap-api-endpoint" title="${_esc(ep.summary ?? '')}">
            <span class="sitemap-method-badge method-${ep.method.toLowerCase()}">${_esc(ep.method)}</span>
            <span class="sitemap-api-path">${_esc(ep.path)}</span>
            ${ep.summary ? `<span class="sitemap-api-summary">${_esc(ep.summary)}</span>` : ''}
          </div>`).join('')}
        ${schema.endpoints.length > 50 ? `<div class="sitemap-api-overflow">+${schema.endpoints.length - 50} more</div>` : ''}
      </div>`;
    $apiContent.appendChild(card);
  }
}

// ─── Context Menu ─────────────────────────────────────────────────────────────

function _showContextMenu(e, url) {
  if (!$contextMenu) return;
  _contextTarget = url;
  $contextMenu.style.left = `${Math.min(e.clientX, window.innerWidth  - 180)}px`;
  $contextMenu.style.top  = `${Math.min(e.clientY, window.innerHeight - 160)}px`;
  $contextMenu.classList.remove('hidden');
}

function _hideContextMenu() {
  $contextMenu?.classList.add('hidden');
  _contextTarget = null;
}

function _safeParseUrl(url) {
  try { return new URL(url); } catch { return null; }
}

function _buildSimpleGetRequest(url) {
  const parsed    = _safeParseUrl(url);
  const pathQuery = parsed ? (parsed.pathname + parsed.search) : '/';
  const host      = parsed ? parsed.host : url;
  const raw       = `GET ${pathQuery} HTTP/1.1\r\nHost: ${host}\r\n\r\n`;
  return { raw, pathQuery, host };
}

function _handleContextAction(action, url) {
  if (!url) return;
  switch (action) {
    case 'open-browser':
      window.electronAPI.openUrl(url);
      break;
    case 'send-repeater': {
      const { raw, pathQuery } = _buildSimpleGetRequest(url);
      document.dispatchEvent(new CustomEvent('repeater:sendTo', {
        detail: { raw, url, label: `GET ${pathQuery}` },
      }));
      break;
    }
    case 'send-intruder': {
      const { raw } = _buildSimpleGetRequest(url);
      document.dispatchEvent(new CustomEvent('intruder:sendTo', { detail: { raw, url } }));
      break;
    }
    case 'send-dirfuzzer':
      // Switch to the Network workspace first so the panel is visible.
      document.querySelector('.workspace-tab[data-workspace="network"]')?.click();
      openDirFuzzPanel(url);
      break;
    case 'api-detect':
      api.crawler.detectApis(url);
      break;
    case 'probe-network':
      _probeHostInNetwork(url);
      break;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Load the full sitemap snapshot from main process on init. */
async function _loadSitemapSnapshot() {
  try {
    const res = await api.crawler.getSitemap();
    if (res.success && res.sitemap) {
      _sitemap = res.sitemap;
      if (res.stats) _stats = res.stats;
      _renderTree();
      _updateStats();
    }
  } catch { /* first launch — empty sitemap is fine */ }
}

function _updateStats() {
  if ($statsHosts) $statsHosts.textContent = `${_stats.hosts ?? Object.keys(_sitemap).length} host${_stats.hosts !== 1 ? 's' : ''}`;
  if ($statsUrls)  $statsUrls.textContent  = `${_stats.urls ?? 0} URL${_stats.urls !== 1 ? 's' : ''}`;
  if ($statsForms) $statsForms.textContent = `${_stats.forms ?? 0} form${_stats.forms !== 1 ? 's' : ''}`;
}

function _firstHost() {
  const hosts = Object.keys(_sitemap);
  return hosts.length > 0 ? `https://${hosts[0]}` : null;
}

function _flushRender() {
  if (_renderTimer) {
    clearTimeout(_renderTimer);
    _renderTimer = null;
  }
  _renderTree();
  _updateStats();
}

function _showCrawlError(message) {
  if (!$crawlError || !$crawlErrorText) return;
  $crawlErrorText.textContent = `⚠️ ${message}`;
  $crawlError.style.display = 'flex';
}

function _showTargetError() {
  if ($targetInput) {
    $targetInput.classList.add('input-error');
    $targetInput.placeholder = 'Enter a target URL first (e.g. https://example.com)';
    setTimeout(() => {
      $targetInput.classList.remove('input-error');
      $targetInput.placeholder = 'https://target.com';
    }, 2500);
  }
}

function _showModal(modal) { modal?.classList.remove('hidden'); }
function _hideModal(modal) { modal?.classList.add('hidden'); }

/** Escape HTML special characters for safe textContent injection. */
function _esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Called from webapp/index.js when the user pivots from the Network workspace.
 * Pre-fills the target input with the given URL.
 */
export function setTargetUrl(url) {
  if ($targetInput) $targetInput.value = url;
}
