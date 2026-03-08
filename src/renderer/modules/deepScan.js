import { state } from '../state.js';

// Cross-module refs injected via init()
let _scanAll = null;
let _debouncedRenderAllHosts = null;
let _updateSecurityBadgeDOM = null;
let _renderActionButtons = null;
let _openDetailsPanel = null;

export function init({ scanAll, debouncedRenderAllHosts, updateSecurityBadgeDOM, renderActionButtons, openDetailsPanel } = {}) {
  _scanAll = scanAll || null;
  _debouncedRenderAllHosts = debouncedRenderAllHosts || null;
  _updateSecurityBadgeDOM = updateSecurityBadgeDOM || null;
  _renderActionButtons = renderActionButtons || null;
  _openDetailsPanel = openDetailsPanel || null;

  // Deep Scan Receivers
  window.electronAPI.onDeepScanProgress && window.electronAPI.onDeepScanProgress((data) => {
    const btnRunDeepScan = document.getElementById('btn-run-deep-scan');
    if (btnRunDeepScan && btnRunDeepScan.getAttribute('data-ip') === data.ip && btnRunDeepScan.getAttribute('data-scanning') === 'true') {
      btnRunDeepScan.innerHTML = `<span class="icon">🛑</span> Cancel Scan (${data.percent}%)`;
    }

    // Update global progress if part of Deep Scan All
    if (_scanAll && _scanAll.state.isRunning && _scanAll.state.active.has(data.ip)) {
      _scanAll.onHostProgress(data.ip, data.percent);
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
            if (badgeContainer && _updateSecurityBadgeDOM) _updateSecurityBadgeDOM(state.hosts[hostIdx], badgeContainer);
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
    if (ip && _renderActionButtons) {
      _renderActionButtons(actionsContainer, ip, data);
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

    if (_scanAll && _scanAll.state.active.has(ip)) {
      _scanAll.onHostProgress(ip, 100); // Force to 100% just in case before removal

      // Delay removal slightly so the UI gets a chance to render 100%
      setTimeout(() => {
        _scanAll.onHostDone(ip);
      }, 500);
    }

    // Refresh the card for this IP so the badge updates and the progress badge is removed
    const card = document.getElementById(`host-${ip.replace(/\./g, '-')}`);
    const host = state.hosts.find(h => h.ip === ip);
    if (card && host) {
       const badgeContainer = card.querySelector('.security-badge-container');
       if (badgeContainer && _updateSecurityBadgeDOM) {
         _updateSecurityBadgeDOM(host, badgeContainer);
       }
    }
  });

  // Nmap Event Receivers
  window.electronAPI.onNmapScanResult && window.electronAPI.onNmapScanResult((data) => {
    let type = data.type;
    const chunk = data.chunk;

    // Parse Progress Stats
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
    if (_scanAll && _scanAll.state.isRunning && _scanAll.state.type !== 'native') {
      const ip = type === 'port' ? data.target.split(':')[0] : data.target;
      if (_scanAll.state.active.has(ip) && timingMatch) {
        _scanAll.onHostProgress(ip, parseFloat(timingMatch[1]));
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
             const stateVal = stateMatch ? stateMatch[1].trim() : 'UNKNOWN';
             const risk = riskMatch ? riskMatch[1].trim().toLowerCase() : 'info'; // default info

             // Deduplicate
             if (!state.hosts[hostIdx].nmapData.vulnerabilities.some(v => v.id === id)) {
                state.hosts[hostIdx].nmapData.vulnerabilities.push({
                   id: id,
                   state: stateVal,
                   severity: risk,
                   details: block.trim()
                });
                newVulnsFound = true;
             }
           }
        });

        // 2. Vulners script table output
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
        if (_debouncedRenderAllHosts) _debouncedRenderAllHosts();

        // Explicitly update the main dashboard Host Card (since debouncedRenderAllHosts only alters display state)
        const card = document.getElementById(`host-${ip.replace(/\./g, '-')}`);
        if (card) {
           const badgeContainer = card.querySelector('.security-badge-container');
           if (badgeContainer && _updateSecurityBadgeDOM) _updateSecurityBadgeDOM(state.hosts[hostIdx], badgeContainer);

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
              if (_openDetailsPanel) _openDetailsPanel(state.hosts[hostIdx]);
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
    if (_scanAll && _scanAll.state.isRunning && _scanAll.state.type !== 'native' && _scanAll.state.active.has(ip)) {
      _scanAll.onHostDone(ip);
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
    if (_scanAll && _scanAll.state.isRunning && _scanAll.state.type !== 'native' && _scanAll.state.active.has(ip)) {
      _scanAll.onHostDone(ip);
    }
  });

  // SNMP Event Receivers
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
}
