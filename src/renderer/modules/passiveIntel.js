import { api } from '../api.js';
import { state } from '../state.js';

// Cross-module ref injected via init()
let _debouncedRenderAllHosts = null;

// --- Panel open/close helpers ---
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

// --- VLAN Discovery state ---
let isVlanCapturing = false;
let vlanTagsDetected = new Set();

const btnToggleVlanPanel = document.getElementById('btn-toggle-vlan-panel');
const vlanPanel = document.getElementById('vlan-panel');
const btnCloseVlanPanel = document.getElementById('btn-close-vlan-panel');
const vlanInterfaceSelect = document.getElementById('vlan-interface-select');
const btnRefreshVlanInterfaces = document.getElementById('btn-refresh-vlan-interfaces');
const btnStartVlanCapture = document.getElementById('btn-start-vlan-capture');
const vlanCountSpan = document.getElementById('vlan-count');
const vlanResultsContainer = document.getElementById('vlan-results-container');
const vlanEmptyState = document.getElementById('vlan-empty-state');

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

// --- SNMP Intel helpers ---
function addDiscoveredHost({ ip, mac, source }) {
  // Re-check for existing host to avoid race duplicates
  const existingIdx = state.hosts.findIndex(h => h.ip === ip);
  if (existingIdx !== -1) {
     // If the host exists but lacks a MAC address, silently enrich it
     if (state.hosts[existingIdx].mac === 'Unknown' && mac) {
        state.hosts[existingIdx].mac = mac;
        console.log(`[SNMP Intel] Enriched existing host MAC via ARP: ${ip}`);
        if (_debouncedRenderAllHosts) _debouncedRenderAllHosts();
     }
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
  if (_debouncedRenderAllHosts) _debouncedRenderAllHosts();
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
    if (_debouncedRenderAllHosts) _debouncedRenderAllHosts();

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

export function init({ debouncedRenderAllHosts } = {}) {
  _debouncedRenderAllHosts = debouncedRenderAllHosts || null;

  // --- VLAN Discovery Wiring ---
  const vlanResizer = document.getElementById('vlan-resizer');

  // Resizer
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
  if (vlanResizer && vlanPanel) {
    vlanResizer.addEventListener('mousedown', (e) => {
      const startWidth = parseInt(document.defaultView.getComputedStyle(vlanPanel).width, 10);
      activeResize = { resizerEl: vlanResizer, panelEl: vlanPanel, startX: e.clientX, startWidth };
      vlanResizer.classList.add('is-resizing');
      document.body.style.cursor = 'col-resize';
      e.preventDefault();
    });
  }

  btnToggleVlanPanel?.addEventListener('click', async () => {
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

  btnCloseVlanPanel?.addEventListener('click', () => {
    closePanel(vlanPanel, document.getElementById('vlan-resizer'));
  });

  btnRefreshVlanInterfaces?.addEventListener('click', refreshVlanInterfaces);

  btnStartVlanCapture?.addEventListener('click', async () => {
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

  // --- Passive Panel Integration ---
  const passiveTabs = document.querySelectorAll('.modal-tab[data-passive-tab]');
  const passiveTabPanes = document.querySelectorAll('.passive-tab-pane');
  const passiveUi = {};
  ['dhcp', 'creds', 'dns', 'arp', 'rogue-dns'].forEach(m => {
    passiveUi[m] = {
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
  const passiveErrorBanner = document.getElementById('passive-error-banner');
  const passiveErrorText = document.getElementById('passive-error-text');
  const btnClosePassiveError = document.getElementById('btn-close-passive-error');
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

  async function handlePassiveToggle(moduleKey, iface) {
    const { requiresConsent, getWaitEl } = passiveModulesConfig[moduleKey];
    const moduleUi = passiveUi[moduleKey];

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
    passiveUi[m].toggle?.addEventListener('change', (e) => {
      handlePassiveToggle(m, passiveInterfaceSelect.value);
    });
  });

  btnAcceptCreds?.addEventListener('click', () => {
    isCredsAccepted = true;
    credDisclaimerBanner.style.display = 'none';
    passiveUi.creds.toggle.checked = true;
    passiveUi.creds.toggle.dispatchEvent(new Event('change'));
  });

  btnRejectCreds?.addEventListener('click', () => {
    credDisclaimerBanner.style.display = 'none';
    passiveUi.creds.toggle.checked = false;
  });

  btnStopAllPassive?.addEventListener('click', async () => {
    await api.stopAllPassive();
    ['dhcp', 'creds', 'dns', 'arp', 'rogue-dns'].forEach(m => {
      passiveUi[m].toggle.checked = false;
      state.passiveModules[m].running = false;
      passiveUi[m].status.textContent = 'Idle';
      passiveUi[m].status.className = 'passive-status';
    });
  });

  // --- Passive Panel Open/Close ---
  const btnTogglePassivePanel = document.getElementById('btn-toggle-passive-panel');
  const passivePanel = document.getElementById('passive-panel');
  const btnClosePassivePanel = document.getElementById('btn-close-passive-panel');
  const btnRefreshPassiveInterfaces = document.getElementById('btn-refresh-passive-interfaces');
  const passiveResizer = document.getElementById('passive-resizer');

  async function refreshPassiveInterfaces() {
    btnRefreshPassiveInterfaces.disabled = true;
    passiveInterfaceSelect.innerHTML = '<option value="">Loading...</option>';
    try {
      const interfaces = await api.getInterfaces();
      passiveInterfaceSelect.innerHTML = '<option value="">Select Interface...</option>';
      interfaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.name;
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

  if (passiveResizer && passivePanel) {
    passiveResizer.addEventListener('mousedown', (e) => {
      const startWidth = parseInt(document.defaultView.getComputedStyle(passivePanel).width, 10);
      activeResize = { resizerEl: passiveResizer, panelEl: passivePanel, startX: e.clientX, startWidth };
      passiveResizer.classList.add('is-resizing');
      document.body.style.cursor = 'col-resize';
      e.preventDefault();
    });
  }

  btnTogglePassivePanel?.addEventListener('click', async () => {
    if (passivePanel.style.display === 'none' || !passivePanel.classList.contains('open')) {
      openPanel(passivePanel, passiveResizer);
      await refreshPassiveInterfaces();
    } else {
      closePanel(passivePanel, passiveResizer);
    }
  });

  btnClosePassivePanel?.addEventListener('click', () => {
    closePanel(passivePanel, passiveResizer);
  });

  btnRefreshPassiveInterfaces?.addEventListener('click', refreshPassiveInterfaces);

  // --- IPC: Passive module events ---
  window.electronAPI.onPassiveDhcpAlert && window.electronAPI.onPassiveDhcpAlert((alert) => {
    state.passiveModules.dhcp.alerts.push(alert);
    passiveUi.dhcp.badge.textContent = state.passiveModules.dhcp.alerts.length;

    if (state.passiveModules.dhcp.alerts.length === 1) passiveUi.dhcp.results.innerHTML = '';

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

    passiveUi.dhcp.results.prepend(el);
  });

  window.electronAPI.onPassiveCredFound && window.electronAPI.onPassiveCredFound((cred) => {
    state.passiveModules.creds.findings.push(cred);
    passiveUi.creds.badge.textContent = state.passiveModules.creds.findings.length;

    if (state.passiveModules.creds.findings.length === 1) passiveUi.creds.results.innerHTML = '';

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

    passiveUi.creds.results.prepend(tr);
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
      if (_debouncedRenderAllHosts) _debouncedRenderAllHosts();
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

    passiveUi.dns.badge.textContent = state.passiveModules.dns.hosts.size;
    passiveUi.dns.results.innerHTML = '';
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

      passiveUi.dns.results.appendChild(tr);
    });
  });

  window.electronAPI.onPassiveArpAlert && window.electronAPI.onPassiveArpAlert((alert) => {
    state.passiveModules.arp.alerts.push(alert);
    passiveUi.arp.badge.textContent = state.passiveModules.arp.alerts.length;

    if (state.passiveModules.arp.alerts.length === 1) passiveUi.arp.results.innerHTML = '';

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

    passiveUi.arp.results.prepend(el);
  });

  window.electronAPI.onPassiveRogueDnsAlert && window.electronAPI.onPassiveRogueDnsAlert((alertMsg) => {
    state.passiveModules['rogue-dns'].alerts.push(alertMsg);
    passiveUi['rogue-dns'].badge.textContent = state.passiveModules['rogue-dns'].alerts.length;

    if (state.passiveModules['rogue-dns'].alerts.length === 1) passiveUi['rogue-dns'].results.innerHTML = '';

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
    passiveUi['rogue-dns'].results.prepend(card);

    if (!alertMsg.isTrusted) passiveUi['rogue-dns'].badge.classList.add('danger');
  });

  window.electronAPI.onPassiveError && window.electronAPI.onPassiveError((err) => {
    passiveErrorText.textContent = err;
    passiveErrorBanner.style.display = 'block';
  });

  // --- SNMP Global Intel Listeners ---
  window.electronAPI.onSnmpIntel && window.electronAPI.onSnmpIntel((intel) => {
    if (intel.type === 'arp-discovery' && intel.discoveredIp) {
      addDiscoveredHost({ ip: intel.discoveredIp, mac: intel.discoveredMac });
    } else {
      updateHostIntelligence(intel.targetIp, intel);
    }
  });
}
