import { elements } from '../ui.js';
import { api } from '../api.js';
import { state } from '../state.js';

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

// Cross-module refs, injected via init()
let _bruteForce = null;
let _dirFuzz = null;
let _shareEnum = null;
let _credSpray = null;
let _hardeningMonitor = null;
let _applySettingsUI = null;
let _updateSecurityBadgeDOM = null;

// --- Hardening Monitor helpers (used in details panel) ---

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

  if (!host.monitorStatus || host.monitorStatus === 'offline') {
    const btnAddToMonitor = document.createElement('button');
    btnAddToMonitor.className = 'btn-action';
    btnAddToMonitor.style.cssText = 'font-size:10px; padding:3px 8px; border-color:var(--success); color:var(--success);';
    btnAddToMonitor.textContent = '➕ Add to Monitor';
    btnAddToMonitor.addEventListener('click', async () => {
      try {
        const existing = await api.hardeningMonitor.getBaseline(subnetGuess);
        const hosts = existing?.hosts || [];
        if (!hosts.some(h => h.ip === host.ip)) {
          hosts.push({
            ip: host.ip, mac: host.mac || '', hostname: host.hostname || '',
            ports: host.ports?.map(p => p.port || p) || [],
            firstSeen: host.firstSeen || Date.now(), lastSeen: host.lastSeen || Date.now(),
          });
        }
        await api.hardeningMonitor.setBaseline(subnetGuess, hosts);
        const idx = state.hosts.findIndex(h => h.ip === host.ip);
        if (idx >= 0) state.hosts[idx].monitorStatus = state.hosts[idx].monitorStatus || 'monitored';
        btnAddToMonitor.textContent = '✓ Added';
        btnAddToMonitor.disabled = true;
      } catch { btnAddToMonitor.textContent = '⚠ Error'; }
    });
    actionRow.appendChild(btnAddToMonitor);
  }

  const btnOpenMonitor = document.createElement('button');
  btnOpenMonitor.className = 'btn-action';
  btnOpenMonitor.style.cssText = 'font-size:10px; padding:3px 8px; border-color:var(--hardening); color:var(--hardening);';
  btnOpenMonitor.textContent = '🛡 Open Monitor Panel';
  btnOpenMonitor.addEventListener('click', () => {
    if (_hardeningMonitor) _hardeningMonitor.openPanel(subnetGuess);
  });
  actionRow.appendChild(btnOpenMonitor);

  const btnMonitorSubnet = document.createElement('button');
  btnMonitorSubnet.className = 'btn-action';
  btnMonitorSubnet.style.cssText = 'font-size:10px; padding:3px 8px;';
  btnMonitorSubnet.textContent = `▶ Monitor ${subnetGuess}`;
  btnMonitorSubnet.addEventListener('click', async () => {
    if (_hardeningMonitor) _hardeningMonitor.openPanel(subnetGuess);
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
        if (typeof _updateSecurityBadgeDOM === 'function') {
          _updateSecurityBadgeDOM(host, badgeContainer);
        }
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
      if (_bruteForce) _bruteForce.openModal(ip, data.port, bfPorts[data.port]);
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
    shareBtn.addEventListener('click', () => {
      if (_shareEnum) _shareEnum.openPanel(host.ip);
    });
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
          if (_dirFuzz) _dirFuzz.openPanel(url);
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
          if (_bruteForce) _bruteForce.openModal(host.ip, port, bfPorts[port]);
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
  if (_applySettingsUI) {
    window.electronAPI.settings.getAll().then(settings => _applySettingsUI(settings));
  }
}

async function refreshSnmpBlacklist() {
  const blacklistStr = await window.electronAPI.settings.get('blacklist');
  return blacklistStr ? blacklistStr.split(',').map(s=>s.trim()) : [];
}

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
    if (_credSpray) _credSpray.openPanel(ip);
  });

  container.append(label, btn);
  return container;
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
      const cachedSnmpBlacklist = await refreshSnmpBlacklist();
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
      if (passivePanel) {
        passivePanel.style.display = 'flex';
        setTimeout(() => passivePanel.classList.add('open'), 10);
        if (passiveResizer) passiveResizer.style.display = 'block';
      }

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

export function init({ bruteForce, dirFuzz, shareEnum, credSpray, hardeningMonitor, applySettingsUI, updateSecurityBadgeDOM } = {}) {
  _bruteForce = bruteForce || null;
  _dirFuzz = dirFuzz || null;
  _shareEnum = shareEnum || null;
  _credSpray = credSpray || null;
  _hardeningMonitor = hardeningMonitor || null;
  _applySettingsUI = applySettingsUI || null;
  _updateSecurityBadgeDOM = updateSecurityBadgeDOM || null;

  elements.btnCloseDetails.addEventListener('click', () => {
    elements.detailsPanel.classList.remove('open');
    const detailsResizer = document.getElementById('sidebar-resizer');
    if (detailsResizer) detailsResizer.style.display = 'none';
    elements.detailsPanel.style.width = '';
  });

  // Resizer logic for details panel
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

  if (elements.sidebarResizer) {
    elements.sidebarResizer.addEventListener('mousedown', (e) => {
      const startWidth = parseInt(document.defaultView.getComputedStyle(elements.detailsPanel).width, 10);
      activeResize = { resizerEl: elements.sidebarResizer, panelEl: elements.detailsPanel, startX: e.clientX, startWidth };
      elements.sidebarResizer.classList.add('is-resizing');
      document.body.style.cursor = 'col-resize';
      e.preventDefault();
    });
  }

  return { openPanel: openDetailsPanel, showHost: openDetailsPanel, renderActionButtons };
}
