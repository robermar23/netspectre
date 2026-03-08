import { elements, domUtils } from '../ui.js';
import { api } from '../api.js';
import { state } from '../state.js';
import { ipRegex, expandCIDR } from '#shared/networkConstants.js';
import { createScanAllOrchestrator } from '../scanAllOrchestrator.js';

// ---- Utility functions local to this module ----

function escapeHtml(unsafe) {
  if (unsafe == null) return '';
  return String(unsafe)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ---- Module-level state ----
let discoverHostCount = 0; // Tracks hosts found during current modal discover session
let renderTimeout;
let scanAllType = 'native'; // 'native' | 'nmap-host' | 'nmap-vuln' | 'nmap-deep'

// Exposed for use by deepScan module
export let scanAll;

// ---- Probe queue ----
const probeQueue = [];
let activeProbes = 0;
const MAX_CONCURRENT_PROBES = 10;

function pumpProbeQueue() {
  while (activeProbes < MAX_CONCURRENT_PROBES && probeQueue.length > 0) {
    const { ip, validIps, completedObj } = probeQueue.shift();
    activeProbes++;
    api.probeHost(ip).then(result => {
      activeProbes--;
      completedObj.count++;
      if (!result || result.error) {
        elements.statusText.innerText = `Probed ${completedObj.count}/${validIps.length} hosts...`;
      } else {
        // Update state with enriched data
        const hostIdx = state.hosts.findIndex(h => h.ip === ip);
        if (hostIdx >= 0) {
          const host = state.hosts[hostIdx];
          if (result.hostname && result.hostname !== 'Unknown') host.hostname = result.hostname;
          if (result.mac) host.mac = result.mac;
          if (result.vendor && result.vendor !== 'Unknown') host.vendor = result.vendor;
          if (result.os && result.os !== 'Unknown OS') host.os = result.os;
          if (result.ports && result.ports.length > 0) host.ports = result.ports;
        }
        // Update card DOM inline
        const card = document.getElementById(`host-${ip.replace(/\./g, '-')}`);
        if (card) {
          const indicator = card.querySelector('.status-indicator');
          if (indicator) {
            indicator.classList.remove('checking');
            indicator.classList.add(result.alive ? 'online' : 'offline');
            indicator.title = result.alive ? `Online (${result.pingTime || '?'}ms)` : 'Offline / Unreachable';
          }
          const nameEl = card.querySelector('.host-name-display');
          if (nameEl && result.hostname) nameEl.textContent = result.hostname;
          const osEl = card.querySelector('.host-os-display');
          if (osEl && result.os) osEl.textContent = result.os;
          const vendorEl = card.querySelector('.host-vendor-display');
          if (vendorEl && result.vendor) vendorEl.textContent = result.vendor;
          const macEl = card.querySelector('.host-mac-display');
          if (macEl && result.mac) macEl.textContent = result.mac;
        }
      }

      if (completedObj.count >= validIps.length) {
        elements.statusText.innerText = `Probe complete. ${completedObj.count} host${completedObj.count !== 1 ? 's' : ''} enriched.`;
      } else {
        elements.statusText.innerText = `Probing... ${completedObj.count}/${validIps.length} hosts complete.`;
      }
      pumpProbeQueue();
    }).catch(() => {
      activeProbes--;
      completedObj.count++;
      pumpProbeQueue();
    });
  }
}

// ---- Scope Modal ----

function openScopeModal() {
  state.pendingHosts = [];
  discoverHostCount = 0;
  elements.scopeModalOverlay.classList.remove('hidden');
  updatePendingCount();
  // Clear previous pending lists
  ['discover-pending-list', 'manual-pending-list', 'import-file-pending-list', 'import-nmap-pending-list'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });
  ['import-file-status', 'import-nmap-status', 'discover-status'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.textContent = ''; el.className = el.id === 'discover-status' ? 'discover-status' : 'import-status'; }
  });
  // Reset manual form
  const manualIp = document.getElementById('manual-ip');
  const manualHostname = document.getElementById('manual-hostname');
  const manualMac = document.getElementById('manual-mac');
  if (manualIp) manualIp.value = '';
  if (manualHostname) manualHostname.value = '';
  if (manualMac) manualMac.value = '';
}

function closeScopeModal() {
  elements.scopeModalOverlay.classList.add('hidden');
  state.pendingHosts = [];
}

function setScopeCommitState({ staged, discovered }) {
  const total = staged + discovered;
  if (discovered > 0 && staged === 0) {
    // Discover-only: hosts are already live on dashboard
    elements.scopePendingCount.textContent = `${discovered} host${discovered !== 1 ? 's' : ''} discovered (added live)`;
    elements.btnScopeCommit.disabled = false;
    elements.btnScopeCommit.innerHTML = '<span class="icon">✅</span> Done';
    return;
  }

  if (total > 0) {
    const parts = [];
    if (staged > 0) parts.push(`${staged} staged`);
    if (discovered > 0) parts.push(`${discovered} discovered`);
    elements.scopePendingCount.textContent = `${total} host${total !== 1 ? 's' : ''} (${parts.join(', ')})`;
    elements.btnScopeCommit.disabled = false;
    elements.btnScopeCommit.innerHTML = staged > 0
      ? '<span class="icon">✅</span> Add to Dashboard'
      : '<span class="icon">✅</span> Done';
  } else {
    elements.scopePendingCount.textContent = '0 hosts staged';
    elements.btnScopeCommit.disabled = true;
    elements.btnScopeCommit.innerHTML = '<span class="icon">✅</span> Add to Dashboard';
  }
}

function updatePendingCount() {
  const staged = state.pendingHosts.length;
  const discovered = discoverHostCount;
  setScopeCommitState({ staged, discovered });
}

function addPendingHost(host, listElId) {
  // Deduplicate by IP
  if (state.pendingHosts.some(h => h.ip === host.ip)) return;
  state.pendingHosts.push(host);
  updatePendingCount();
  renderPendingItem(host, listElId);
}

function renderPendingItem(host, listElId) {
  const listEl = document.getElementById(listElId);
  if (!listEl) return;
  const item = document.createElement('div');
  item.className = 'pending-host-item';
  item.setAttribute('data-ip', host.ip);

  const infoSpan = document.createElement('span');
  const ipSpan = document.createElement('span');
  ipSpan.className = 'pending-ip';
  ipSpan.textContent = host.ip;
  infoSpan.appendChild(ipSpan);

  if (host.hostname) {
    const metaSpan = document.createElement('span');
    metaSpan.className = 'pending-meta';
    metaSpan.textContent = host.hostname;
    infoSpan.appendChild(metaSpan);
  }
  if (host.os) {
    const osSpan = document.createElement('span');
    osSpan.className = 'pending-meta';
    osSpan.textContent = `| ${host.os}`;
    infoSpan.appendChild(osSpan);
  }

  const removeBtn = document.createElement('button');
  removeBtn.className = 'btn-remove-pending';
  removeBtn.textContent = '✕';
  removeBtn.addEventListener('click', () => {
    state.pendingHosts = state.pendingHosts.filter(h => h.ip !== host.ip);
    item.remove();
    updatePendingCount();
  });

  item.appendChild(infoSpan);
  item.appendChild(removeBtn);
  listEl.appendChild(item);
}

// ---- Blacklist ----

function isBlacklisted(host) {
  if (state.blacklist.length === 0) return false;
  for (const entry of state.blacklist) {
    if (entry === host.ip) return true;
    if (host.mac && entry.toUpperCase() === host.mac.toUpperCase()) return true;
    if (entry.includes('/')) {
      const [net, bits] = entry.split('/');
      const prefix = parseInt(bits, 10);
      if (!isNaN(prefix) && prefix >= 8 && prefix <= 32) {
        const netParts = net.split('.').map(Number);
        const hostParts = host.ip.split('.').map(Number);
        if (netParts.length === 4 && hostParts.length === 4) {
          const netNum = ((netParts[0] << 24) | (netParts[1] << 16) | (netParts[2] << 8) | netParts[3]) >>> 0;
          const hostNum = ((hostParts[0] << 24) | (hostParts[1] << 16) | (hostParts[2] << 8) | hostParts[3]) >>> 0;
          const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
          if ((netNum & mask) === (hostNum & mask)) return true;
        }
      }
    }
  }
  return false;
}

function renderBlacklistEntries() {
  elements.blacklistEntries.innerHTML = '';
  state.blacklist.forEach((entry, idx) => {
    const el = document.createElement('div');
    el.className = 'blacklist-entry';
    const label = document.createElement('span');
    label.textContent = `🚫 ${entry}`;
    const removeBtn = document.createElement('button');
    removeBtn.className = 'btn-remove-bl';
    removeBtn.textContent = '✕';
    removeBtn.addEventListener('click', () => {
      state.blacklist.splice(idx, 1);
      renderBlacklistEntries();
      renderAllHosts();
    });
    el.appendChild(label);
    el.appendChild(removeBtn);
    elements.blacklistEntries.appendChild(el);
  });
  elements.blacklistCount.textContent = `${state.blacklist.length} entr${state.blacklist.length !== 1 ? 'ies' : 'y'}`;
}

// ---- Host Card Rendering ----

function getSecurityBadgeData(host) {
  let posture = 'Unknown';
  let badgeClass = 'secondary';
  let icon = '❔';

  // Monitor state takes highest priority in the badge
  if (host.monitorStatus === 'offline') {
    return { posture: 'Offline', badgeClass: 'danger', icon: '💀' };
  }
  if (host.monitorAlerts?.length > 0) {
    const hasCritical = host.monitorAlerts.some(a => a.severity === 'critical');
    return {
      posture:    hasCritical ? 'Delta: Critical' : 'Delta: Warning',
      badgeClass: hasCritical ? 'danger' : 'warning',
      icon:       hasCritical ? '🔴' : '🟡',
    };
  }

  if (host.deepAudit && host.deepAudit.vulnerabilities > 0) {
    posture = `${host.deepAudit.vulnerabilities} Critical/High CVEs`;
    badgeClass = 'danger';
    icon = '🛑';
  } else if (host.deepAudit && host.deepAudit.warnings > 0) {
    posture = `${host.deepAudit.warnings} Medium/Low CVEs`;
    badgeClass = 'warning';
    icon = '⚠️';
  } else if ((host.deepAudit && host.deepAudit.history && host.deepAudit.history.length > 0) || (host.nmapData && host.nmapData.vuln)) {
    posture = 'Audited Secure';
    badgeClass = 'success';
    icon = '🛡️';
  } else if (host.ports && host.ports.length > 0) {
    const p = new Set(host.ports);
    if (p.has(21) || p.has(23) || p.has(3306) || p.has(1433) || p.has(27017)) {
      posture = 'Risky Ports';
      badgeClass = 'danger';
      icon = '🛑';
    } else if (p.has(80) || p.has(445) || p.has(135)) {
      posture = 'Exposed Services';
      badgeClass = 'warning';
      icon = '⚠️';
    } else {
      posture = 'Unscanned';
      badgeClass = 'secondary';
      icon = '❔';
    }
  } else {
    posture = 'Unscanned';
    badgeClass = 'secondary';
    icon = '❔';
  }

  return { posture, badgeClass, icon };
}

export function updateSecurityBadgeDOM(host, container) {
  if (!container) return;
  const data = getSecurityBadgeData(host);
  const badgeSpan = document.createElement('span');
  badgeSpan.className = 'security-badge-span';
  badgeSpan.style.cssText = `font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--${data.badgeClass}); color: var(--${data.badgeClass}); background: rgba(0,0,0,0.2);`;
  badgeSpan.textContent = `${data.icon} ${data.posture}`;

  container.innerHTML = '';
  container.appendChild(badgeSpan);
}

const MONITOR_STATUS_MAP = {
  online:  { className: 'mon-online',  title: lastSeen => `Monitor: online · ${fmtTime(lastSeen)}` },
  offline: { className: 'mon-offline', title: lastSeen => `Monitor: offline · last seen ${fmtTime(lastSeen)}` },
  changed: { className: 'mon-changed', title: lastSeen => `Monitor: state changed · ${fmtTime(lastSeen)}` },
};

export function updateMonitorDotDOM(host, card) {
  if (!host.monitorStatus || !card) return;
  let dot = card.querySelector('.host-monitor-dot');
  if (!dot) {
    dot = document.createElement('span');
    dot.className = 'host-monitor-dot';
    card.querySelector('.host-header')?.appendChild(dot);
  }
  dot.className = 'host-monitor-dot';
  const cfg = MONITOR_STATUS_MAP[host.monitorStatus];
  if (cfg) {
    dot.classList.add(cfg.className);
    dot.title = cfg.title(host.monitorLastSeen);
  }
}

function buildHostCard(host) {
  const card = document.createElement('div');
  card.className = 'host-card glass-panel';
  card.id = `host-${host.ip.replace(/\./g, '-')}`;
  if (host.monitorStatus) card.dataset.monitorStatus = host.monitorStatus;

  card.innerHTML = `
    <div class="status-indicator checking" title="Checking connectivity..."></div>
    <button class="btn-remove-host" title="Remove host">✕</button>
    <div class="host-header">
      <h3 class="host-ip-display"></h3>
      <p class="mac host-mac-display"></p>
    </div>
    <div class="host-body">
      <div class="info-row"><span class="label">Hostname:</span> <span class="value host-name-display"></span></div>
      <div class="info-row"><span class="label">OS:</span> <span class="value host-os-display"></span></div>
      <div class="info-row"><span class="label">Vendor:</span> <span class="value host-vendor-display"></span></div>
      <div class="security-badge-container"></div>
    </div>
    <div class="host-footer" style="padding-top: 8px;">
      <button class="btn info full-width btn-view">View Details</button>
    </div>
  `;
  card.querySelector('.host-ip-display').textContent = host.ip;
  card.querySelector('.host-mac-display').textContent = host.mac || 'Unknown MAC';
  card.querySelector('.host-name-display').textContent = host.hostname || 'Unknown';
  card.querySelector('.host-os-display').textContent = host.os || 'Unknown';
  card.querySelector('.host-vendor-display').textContent = host.vendor || 'Unknown';
  updateSecurityBadgeDOM(host, card.querySelector('.security-badge-container'));
  updateMonitorDotDOM(host, card);

  return card;
}

// openDetailsPanel is provided by hostDetails module via the returned interface
// We use an internal variable that gets set during init
let _openDetailsPanel = null;

export function setOpenDetailsPanelRef(fn) {
  _openDetailsPanel = fn;
}

function attachHostCardBehavior(card, host) {
  // Add source badge next to IP if not discovered
  if (host.source && host.source !== 'discovered') {
    const badge = document.createElement('span');
    badge.className = `source-badge ${host.source}`;
    const sourceLabels = { manual: '📌 Manual', imported: '📄 Imported', 'nmap-import': '📥 Nmap' };
    badge.textContent = sourceLabels[host.source] || host.source;
    card.querySelector('.host-ip-display').appendChild(badge);
  }

  card.querySelector('.btn-view').addEventListener('click', () => {
    if (_openDetailsPanel) _openDetailsPanel(host);
  });

  // Remove host button
  card.querySelector('.btn-remove-host').addEventListener('click', (e) => {
    e.stopPropagation();
    state.hosts = state.hosts.filter(h => h.ip !== host.ip);
    card.remove();
    renderAllHosts();
  });

  // Async ping check for real connectivity
  if (ipRegex.test(host.ip)) {
    api.pingHost(host.ip).then(result => {
      const indicator = card.querySelector('.status-indicator');
      if (!indicator) return;
      indicator.classList.remove('checking');
      if (result && result.alive) {
        indicator.classList.add('online');
        indicator.title = `Online (${result.time}ms)`;
      } else {
        indicator.classList.add('offline');
        indicator.title = 'Offline / Unreachable';
      }
    }).catch(() => {
      const indicator = card.querySelector('.status-indicator');
      if (indicator) {
        indicator.classList.remove('checking');
        indicator.classList.add('offline');
        indicator.title = 'Ping failed';
      }
    });
  }
}

function createHostCardDOM(host) {
  const card = buildHostCard(host);
  attachHostCardBehavior(card, host);
  return card;
}

export function getFilteredAndSortedHosts() {
  const ipTerm = elements.filterIp.value.toLowerCase();
  const osTerm = elements.filterOs.value.toLowerCase();
  const vendorTerm = elements.filterVendor.value.toLowerCase();

  let filteredHosts = state.hosts.filter((h) => {
    // Blacklist enforcement
    if (isBlacklisted(h)) return false;
    const matchIp = h.ip ? h.ip.toLowerCase().includes(ipTerm) : false;
    const matchOs = h.os ? String(h.os).toLowerCase().includes(osTerm) : false;
    const matchVendor = h.vendor ? String(h.vendor).toLowerCase().includes(vendorTerm) : false;
    return (ipTerm === '' || matchIp) && (osTerm === '' || matchOs) && (vendorTerm === '' || matchVendor);
  });

  const sortBy = elements.sortSelect.value;
  filteredHosts.sort((a, b) => {
    let valA = a[sortBy] || '';
    let valB = b[sortBy] || '';
    if (sortBy === 'ip') {
      try {
        const numA = Number(valA.split('.').map(n => (`000${n}`).slice(-3)).join(''));
        const numB = Number(valB.split('.').map(n => (`000${n}`).slice(-3)).join(''));
        valA = numA; valB = numB;
      } catch (e) {}
    } else {
      valA = String(valA).toLowerCase();
      valB = String(valB).toLowerCase();
    }
    if (valA < valB) return state.sortDirection === 'asc' ? -1 : 1;
    if (valA > valB) return state.sortDirection === 'asc' ? 1 : -1;
    return 0;
  });
  return filteredHosts;
}

export function renderAllHosts() {
  const filteredHosts = getFilteredAndSortedHosts();
  elements.resultCountText.innerText = `Showing ${filteredHosts.length} of ${state.hosts.length} hosts`;

  if (filteredHosts.length > 0) {
    elements.scanAllGroup.style.display = 'inline-flex';
    elements.emptyState.classList.add('hidden');
  } else {
    elements.scanAllGroup.style.display = 'none';
    if (state.hosts.length === 0) {
      elements.emptyState.classList.remove('hidden');
    } else {
      elements.emptyState.classList.add('hidden');
    }
  }

  domUtils.applyViewStyle(state);

  const allCards = Array.from(elements.hostGrid.querySelectorAll('.host-card'));
  allCards.forEach(c => c.style.display = 'none');

  filteredHosts.forEach(host => {
    let card = document.getElementById(`host-${host.ip.replace(/\./g, '-')}`);
    if (!card) {
      card = createHostCardDOM(host);
    } else {
      card.style.display = '';
    }
    elements.hostGrid.appendChild(card);
  });
}

export function debouncedRenderAllHosts() {
  clearTimeout(renderTimeout);
  renderTimeout = setTimeout(() => renderAllHosts(), 100);
}

export function clearGrid() {
  state.hosts = [];
  elements.hostGrid.innerHTML = '';
  domUtils.applyViewStyle(state);
  elements.emptyState.classList.remove('hidden');
  elements.detailsPanel.classList.remove('open');
  elements.statusText.innerText = 'Ready to scan.';
  domUtils.setScanningState(false, state);
}

export function init({ openDetailsPanel } = {}) {
  if (openDetailsPanel) {
    _openDetailsPanel = openDetailsPanel;
  }

  // View toggles
  elements.btnViewGrid.addEventListener('click', () => { state.currentView = 'grid'; domUtils.applyViewStyle(state); });
  elements.btnViewList.addEventListener('click', () => { state.currentView = 'list'; domUtils.applyViewStyle(state); });
  elements.btnViewTable.addEventListener('click', () => { state.currentView = 'table'; domUtils.applyViewStyle(state); });
  elements.btnViewTopology.addEventListener('click', () => {
    state.currentView = 'topology';
    domUtils.applyViewStyle(state);
    import('../topology.js').then(m => m.updateTopologyData(state.hosts));
  });

  document.addEventListener('open-host-details', (e) => {
    const ip = e.detail;
    const host = state.hosts.find(h => h.ip === ip);
    if (host && _openDetailsPanel) _openDetailsPanel(host);
  });

  // Interface loading
  async function initInterfaces() {
    try {
      const interfaces = await api.getInterfaces();
      elements.interfaceSelect.innerHTML = '';

      if (interfaces.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No interfaces found';
        elements.interfaceSelect.appendChild(opt);
        return;
      }

      interfaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.subnet;
        opt.textContent = iface.label;
        elements.interfaceSelect.appendChild(opt);
      });

      elements.interfaceSelect.disabled = false;
      elements.btnScan.disabled = false;
    } catch (e) {
      console.error('Failed to load interfaces:', e);
      elements.interfaceSelect.innerHTML = '<option value="">Error loading</option>';
    }
  }

  initInterfaces();

  elements.btnRefreshInterfaces.addEventListener('click', () => {
    elements.interfaceSelect.innerHTML = '<option value="">Refreshing...</option>';
    elements.interfaceSelect.disabled = true;
    elements.btnScan.disabled = true;
    initInterfaces();
  });

  // Tab switching inside scope modal
  document.querySelectorAll('.modal-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const pane = document.getElementById(`tab-${tab.getAttribute('data-tab')}`);
      if (pane) pane.classList.add('active');
    });
  });

  // Open/Close scope modal
  elements.btnAddHosts.addEventListener('click', openScopeModal);
  if (elements.btnAddHostsCta) elements.btnAddHostsCta.addEventListener('click', openScopeModal);
  elements.btnCloseScopeModal.addEventListener('click', closeScopeModal);
  elements.btnScopeCancel.addEventListener('click', closeScopeModal);

  // Commit pending hosts to dashboard
  elements.btnScopeCommit.addEventListener('click', () => {
    const newHosts = [...state.pendingHosts];
    const hostsToProbe = [];
    newHosts.forEach(h => {
      const existingIdx = state.hosts.findIndex(existing => existing.ip === h.ip);
      if (existingIdx >= 0) {
        state.hosts[existingIdx] = { ...state.hosts[existingIdx], ...h };
      } else {
        state.hosts.push(h);
      }
      // Queue non-discovered hosts for auto-probe
      if (h.source && h.source !== 'discovered') {
        hostsToProbe.push(h.ip);
      }
    });
    elements.statusText.innerText = `Added ${newHosts.length} host${newHosts.length !== 1 ? 's' : ''} to scope.`;
    closeScopeModal();
    renderAllHosts();

    // Auto-probe each non-discovered host in the background
    if (hostsToProbe.length > 0) {
      const validIps = hostsToProbe.filter(ip => ipRegex.test(ip));
      if (validIps.length > 0) {
        elements.statusText.innerText = `Probing ${validIps.length} host${validIps.length !== 1 ? 's' : ''}...`;
        const completedObj = { count: 0 };
        validIps.forEach(ip => {
          probeQueue.push({ ip, validIps, completedObj });
        });
        pumpProbeQueue();
      }
    }
  });

  // Manual Entry Tab
  document.getElementById('btn-manual-add')?.addEventListener('click', () => {
    const ipInput = document.getElementById('manual-ip');
    const hostnameInput = document.getElementById('manual-hostname');
    const macInput = document.getElementById('manual-mac');
    const ipVal = ipInput.value.trim();
    if (!ipVal) { ipInput.focus(); return; }

    if (ipVal.includes('/')) {
      // CIDR: expand to individual IPs
      const expanded = expandCIDR(ipVal);
      if (expanded.length === 0) {
        ipInput.style.borderColor = 'var(--danger)';
        setTimeout(() => { ipInput.style.borderColor = ''; }, 2000);
        return;
      }
      expanded.forEach(ip => {
        addPendingHost({ ip, hostname: '', mac: '', vendor: '', os: '', source: 'manual' }, 'manual-pending-list');
      });
    } else {
      // Single host
      const host = {
        ip: ipVal,
        hostname: hostnameInput.value.trim() || '',
        mac: macInput.value.trim() || '',
        vendor: '',
        os: '',
        source: 'manual'
      };
      addPendingHost(host, 'manual-pending-list');
    }
    ipInput.value = '';
    hostnameInput.value = '';
    macInput.value = '';
    ipInput.focus();
  });

  // Import File Tab
  document.getElementById('btn-browse-scope')?.addEventListener('click', async () => {
    const statusEl = document.getElementById('import-file-status');
    statusEl.textContent = 'Importing...';
    statusEl.className = 'import-status';
    const res = await api.importScopeFile();
    if (res.status === 'imported') {
      statusEl.textContent = `✅ Imported ${res.hosts.length} hosts from ${res.path.split(/[\\/]/).pop()}`;
      statusEl.className = 'import-status success';
      res.hosts.forEach(h => addPendingHost(h, 'import-file-pending-list'));
    } else if (res.status === 'error') {
      statusEl.textContent = `❌ Error: ${res.error}`;
      statusEl.className = 'import-status error';
    } else {
      statusEl.textContent = '';
      statusEl.className = 'import-status';
    }
  });

  // Import Nmap XML Tab
  document.getElementById('btn-browse-nmap')?.addEventListener('click', async () => {
    const statusEl = document.getElementById('import-nmap-status');
    statusEl.textContent = 'Parsing XML...';
    statusEl.className = 'import-status';
    const res = await api.importNmapXml();
    if (res.status === 'imported') {
      statusEl.textContent = `✅ Parsed ${res.hosts.length} hosts from ${res.path.split(/[\\/]/).pop()}`;
      statusEl.className = 'import-status success';
      res.hosts.forEach(h => addPendingHost(h, 'import-nmap-pending-list'));
    } else if (res.status === 'error') {
      statusEl.textContent = `❌ Error: ${res.error}`;
      statusEl.className = 'import-status error';
    } else {
      statusEl.textContent = '';
      statusEl.className = 'import-status';
    }
  });

  // Blacklist
  elements.btnBlacklist.addEventListener('click', () => {
    elements.blacklistModalOverlay.classList.remove('hidden');
    renderBlacklistEntries();
  });

  elements.btnCloseBlacklistModal.addEventListener('click', () => {
    elements.blacklistModalOverlay.classList.add('hidden');
  });

  elements.btnBlacklistDone.addEventListener('click', () => {
    elements.blacklistModalOverlay.classList.add('hidden');
    renderAllHosts();
  });

  elements.btnBlacklistAdd.addEventListener('click', () => {
    const val = elements.blacklistInput.value.trim();
    if (!val) return;
    if (state.blacklist.includes(val)) return;
    state.blacklist.push(val);
    elements.blacklistInput.value = '';
    renderBlacklistEntries();
  });

  elements.blacklistInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') elements.btnBlacklistAdd.click();
  });

  // Filters + Sort
  elements.filterIp.addEventListener('input', renderAllHosts);
  elements.filterOs.addEventListener('input', renderAllHosts);
  elements.filterVendor.addEventListener('input', renderAllHosts);
  elements.sortSelect.addEventListener('change', renderAllHosts);

  elements.btnSortDir.addEventListener('click', () => {
    state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
    elements.btnSortDir.innerText = state.sortDirection === 'asc' ? '⬇️' : '⬆️';
    renderAllHosts();
  });

  // Scan All orchestrator
  scanAll = createScanAllOrchestrator({
    api,
    elements,
    getHosts: getFilteredAndSortedHosts,
    updateUI: () => {
      if (!scanAll.state.isRunning) {
        const labelText = document.querySelector('.scan-all-option.active')?.getAttribute('data-label') || 'Deep Scan All';
        const iconMap = { native: '⚡', 'nmap-host': '🖥️', 'nmap-vuln': '🛡️', 'nmap-deep': '☢️' };
        elements.btnDeepScanAll.querySelector('.icon').textContent = iconMap[scanAll.state.type] || '⚡';
        elements.scanAllLabel.textContent = labelText;
        if (scanAll.state.total > 0 && scanAll.state.completed === scanAll.state.total) {
          elements.statusText.innerText = `Scan all finished (${scanAll.state.total} hosts).`;
        }
        return;
      }

      // Calculate global percentage based on completed and active
      let activePercentageSum = 0;
      for (const ip of scanAll.state.active) {
        if (scanAll.state.hostProgress[ip] !== undefined) activePercentageSum += scanAll.state.hostProgress[ip];
      }
      let totalPercentageVal = 0;
      if (scanAll.state.total > 0) {
        const totalMaxProgress = scanAll.state.total * 100;
        const currentProgressTotal = (scanAll.state.completed * 100) + activePercentageSum;
        totalPercentageVal = Math.round((currentProgressTotal / totalMaxProgress) * 100);
      }

      if (scanAll.state.type === 'native') {
        elements.statusText.innerText = `Deep scanning: ${scanAll.state.completed}/${scanAll.state.total} hosts completed - ${totalPercentageVal}%`;
      } else {
        const activeList = [...scanAll.state.active].map(aip => {
          const p = scanAll.state.hostProgress[aip];
          return p !== undefined ? `${aip} (${p.toFixed(0)}%)` : aip;
        }).join(', ');
        const scanLabel = `Nmap ${scanAll.state.type.replace('nmap-', '')} scan`;
        elements.statusText.innerText = `${scanLabel}: ${scanAll.state.completed}/${scanAll.state.total} done | Active: ${activeList}`;
      }

      // Sync abort button state
      elements.btnDeepScanAll.querySelector('.icon').textContent = '🛑';
      elements.scanAllLabel.textContent = `Cancel (${scanAll.state.completed}/${scanAll.state.total})`;
    }
  });

  elements.btnScanAllMenu.addEventListener('click', (e) => {
    e.stopPropagation();
    elements.scanAllDropdown.classList.toggle('hidden');
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.scan-all-group')) {
      elements.scanAllDropdown.classList.add('hidden');
    }
  });

  document.querySelectorAll('.scan-all-option').forEach(opt => {
    opt.addEventListener('click', () => {
      document.querySelectorAll('.scan-all-option').forEach(o => o.classList.remove('active'));
      opt.classList.add('active');
      scanAllType = opt.getAttribute('data-scan-type');
      scanAll.setType(scanAllType);
      const label = opt.getAttribute('data-label');
      elements.scanAllLabel.textContent = label;
      const iconMap = { native: '⚡', 'nmap-host': '🖥️', 'nmap-vuln': '🛡️', 'nmap-deep': '☢️' };
      elements.btnDeepScanAll.querySelector('.icon').textContent = iconMap[scanAllType] || '⚡';
      elements.scanAllDropdown.classList.add('hidden');
    });
  });

  elements.btnDeepScanAll.addEventListener('click', () => {
    if (scanAll.state.isRunning) {
      scanAll.cancel();
      return;
    }
    scanAll.start();
  });

  // Main scan controls
  elements.btnScan.addEventListener('click', async () => {
    const subnet = elements.interfaceSelect.value;
    if (!subnet) return alert('Select interface first.');
    domUtils.setScanningState(true, state);
    await api.scanNetwork(subnet);
  });

  elements.btnStop.addEventListener('click', async () => {
    domUtils.setScanningState(false, state);
    await api.stopScan();
  });

  elements.btnSave.addEventListener('click', async () => {
    const res = await api.saveResults(state.hosts);
    if (res.status === 'saved') elements.statusText.innerText = `Saved to ${res.path}`;
  });

  elements.btnLoad.addEventListener('click', async () => {
    const res = await api.loadResults();
    if (res.status === 'loaded' && res.data) {
      clearGrid();
      state.hosts = res.data;
      renderAllHosts();
    }
  });

  elements.btnClear.addEventListener('click', async () => {
    clearGrid();
    await api.clearResults();
  });

  elements.btnExit.addEventListener('click', () => {
    api.exitApp();
  });

  // IPC event listeners
  if (window.electronAPI) {
    window.electronAPI.onHostFound((hostData) => {
      const existingIdx = state.hosts.findIndex(h => h.ip === hostData.ip);
      if (existingIdx >= 0) {
        state.hosts[existingIdx] = {
          ...state.hosts[existingIdx],
          ...hostData,
          routing: state.hosts[existingIdx].routing || [],
          processes: state.hosts[existingIdx].processes || []
        };
      } else {
        state.hosts.push({
          ...hostData,
          routing: hostData.routing || [],
          processes: hostData.processes || []
        });
      }
      debouncedRenderAllHosts();

      // If scope modal is open, track discovered hosts for the footer counter
      if (!elements.scopeModalOverlay.classList.contains('hidden')) {
        discoverHostCount++;
        const discoverStatus = document.getElementById('discover-status');
        if (discoverStatus) {
          discoverStatus.textContent = `Discovered ${discoverHostCount} host${discoverHostCount !== 1 ? 's' : ''} so far...`;
        }
        updatePendingCount();
      }
    });

    window.electronAPI.onScanComplete(({ message }) => {
      domUtils.setScanningState(false, state);
      elements.statusText.innerText = message || `Scan complete. Found ${state.hosts.length} hosts.`;
    });

    window.electronAPI.onScanError(({ error }) => {
      domUtils.setScanningState(false, state);
      elements.statusText.innerText = `Scan error: ${error}`;
    });
  }

  return { renderAllHosts, clearGrid };
}
