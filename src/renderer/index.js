// =============================================
// NetSpecter Renderer — Orchestrator
// =============================================
// This file initializes all feature modules in
// dependency order and wires cross-module refs.
// All feature logic lives in ./modules/*.js
// =============================================

import { init as initApp } from './modules/init.js';
import { init as initSettings, applySettingsUI } from './modules/settings.js';
import {
  init as initScanControls,
  debouncedRenderAllHosts,
  updateSecurityBadgeDOM,
  updateMonitorDotDOM,
  setOpenDetailsPanelRef,
  scanAll,
} from './modules/scanControls.js';
import { init as initBruteForce } from './modules/bruteForce.js';
import { init as initMetasploit } from './modules/metasploit.js';
import { init as initRevShell } from './modules/revShell.js';
import { init as initShareEnum } from './modules/shareEnum.js';
import { init as initDirFuzz } from './modules/dirFuzz.js';
import { init as initCredSpray } from './modules/credSpray.js';
import { init as initHardeningMonitor, setOpenDetailsPanelRef as setHardeningDetailsPanelRef } from './modules/hardeningMonitor.js';
import { init as initCloudEnum } from './modules/cloudEnum.js';
import { init as initHostDetails } from './modules/hostDetails.js';
import { init as initDeepScan } from './modules/deepScan.js';
import { init as initPassiveIntel } from './modules/passiveIntel.js';
import { init as initPcap } from './modules/pcap.js';
import { init as initWebApp } from './modules/webapp/index.js';
import { reapplyWebVulnBadges } from './modules/webapp/scanner.js';

// --- Boot Sequence ---

async function boot() {
  // 1. Dependency checks, missing-tool banner, state flags (async)
  await initApp();

  // 2. Settings modal (no deps)
  initSettings();

  // 3. Pentest panel modules (no inter-module deps)
  const bruteForce   = initBruteForce();
  const metasploit   = initMetasploit();   // eslint-disable-line no-unused-vars
  const revShell     = initRevShell();     // eslint-disable-line no-unused-vars
  const shareEnum    = initShareEnum();
  const dirFuzz      = initDirFuzz();
  const credSpray    = initCredSpray();
  const cloudEnum    = initCloudEnum();

  // 4. Hardening monitor (needs renderAllHosts helpers)
  const hardeningMonitor = initHardeningMonitor({
    debouncedRenderAllHosts,
    updateSecurityBadgeDOM,
    updateMonitorDotDOM,
  });

  // 5. Host details panel (needs cross-module panel openers + applySettingsUI)
  const hostDetails = initHostDetails({
    bruteForce,
    dirFuzz,
    shareEnum,
    credSpray,
    hardeningMonitor,
    cloudEnum,
    applySettingsUI,
    updateSecurityBadgeDOM,
  });

  // 6. Scan controls — host grid, scope modal, scan-all orchestrator, scan IPC events.
  //    Pass openDetailsPanel so "View Details" card buttons work.
  //    Pass onHostsRendered so cloud-enum badges survive re-renders.
  initScanControls({
    openDetailsPanel: hostDetails.openPanel,
    onHostsRendered: () => {
      cloudEnum.reapplyBadges();
      reapplyWebVulnBadges();
    },
  });

  // 7. Wire openDetailsPanel into both scanControls (for late-rendered host cards)
  //    and hardeningMonitor (for "Investigate" alert buttons).
  //    Also expose globally for cross-module callers (CloudEnum "Scan Host" button).
  window.__openDetailsPanel = hostDetails.openPanel;
  setOpenDetailsPanelRef(hostDetails.openPanel);
  setHardeningDetailsPanelRef(hostDetails.openPanel);

  // 8. Deep scan IPC receivers
  initDeepScan({
    scanAll,
    debouncedRenderAllHosts,
    updateSecurityBadgeDOM,
    renderActionButtons: hostDetails.renderActionButtons,
    openDetailsPanel:    hostDetails.openPanel,
  });

  // 9. Passive intel, VLAN discovery, SNMP intel listeners
  initPassiveIntel({ debouncedRenderAllHosts });

  // 10. PCAP live capture and file import/export modal
  initPcap();

  // 11. Web App workspace (Feature 7) — workspace switcher, sidebar, proxy UI
  initWebApp();

  // 12. Cross-workspace: Scanner "Probe in Network" injects hosts from L7 → L3/L4
  window.addEventListener('network:hostAdded', () => debouncedRenderAllHosts());
}

boot().catch(err => console.error('[NetSpecter] Boot error:', err));
