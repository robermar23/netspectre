/**
 * webapp/index.js — Web App Workspace Orchestrator
 * Bootstraps the workspace-switcher, sidebar navigation,
 * and all sub-module inits for Feature 7.
 */

import { state } from '../../state.js';
import { init as initProxy }                              from './proxy.js';
import { init as initSitemap, setTargetUrl as setSitemapTarget } from './sitemap.js';
import { init as initScanner, scanUrl }                  from './scanner.js';
import { init as initRepeater, openTab as openRepeaterTab } from './repeater.js';
import { init as initIntruder, openWithRequest as openIntruderWith } from './intruder.js';
import { init as initSequencer }                         from './sequencer.js';
import { init as initDecoder }                           from './decoder.js';
import { init as initComparer }                          from './comparer.js';

// ─── Workspace Switcher ────────────────────────────────────────────────────────

function _initWorkspaceSwitcher() {
  const tabs       = document.querySelectorAll('.workspace-tab');
  const networkWs  = document.getElementById('ws-network');
  const webappWs   = document.getElementById('ws-webapp');

  if (!tabs.length || !networkWs) return;

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const ws = tab.dataset.workspace;
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeWorkspace = ws;

      if (ws === 'network') {
        networkWs.style.display = '';
        networkWs.classList.add('active');
        if (webappWs) { webappWs.style.display = 'none'; webappWs.classList.remove('active'); }
      } else if (ws === 'webapp') {
        if (webappWs) { webappWs.style.display = ''; webappWs.classList.add('active'); }
        networkWs.style.display = 'none';
        networkWs.classList.remove('active');
      }
    });
  });
}

// ─── Sidebar Navigation ────────────────────────────────────────────────────────

function _initSidebar() {
  const sidebarItems = document.querySelectorAll('#webapp-sidebar .sidebar-item');
  const panels       = document.querySelectorAll('#webapp-main .webapp-panel');
  const toggleBtn    = document.getElementById('webapp-sidebar-toggle');
  const sidebar      = document.getElementById('webapp-sidebar');

  sidebarItems.forEach(item => {
    item.addEventListener('click', () => {
      const panelId = `webapp-panel-${item.dataset.panel}`;

      sidebarItems.forEach(i => i.classList.remove('active'));
      item.classList.add('active');

      panels.forEach(p => {
        p.style.display = p.id === panelId ? 'flex' : 'none';
        p.classList.toggle('active', p.id === panelId);
      });
    });
  });

  // Sidebar collapse/expand
  if (toggleBtn && sidebar) {
    let collapsed = false;
    toggleBtn.addEventListener('click', () => {
      collapsed = !collapsed;
      sidebar.classList.toggle('collapsed', collapsed);
      toggleBtn.textContent = collapsed ? '›' : '‹';
    });
  }
}

// ─── Network Workspace Pivot ───────────────────────────────────────────────────

/**
 * Called from hostDetails.js when user clicks "Open in Web App".
 * Pre-fills the proxy target and switches workspace.
 */
export function openInWebApp(url) {
  // Switch to webapp workspace
  const webappTab = document.querySelector('.workspace-tab[data-workspace="webapp"]');
  webappTab?.click();

  // Switch to proxy panel in the sidebar
  const proxyItem = document.querySelector('#webapp-sidebar .sidebar-item[data-panel="proxy"]');
  proxyItem?.click();

  // Pre-fill port if URL has a custom port
  try {
    const parsed = new URL(url);
    const portInput = document.getElementById('proxy-port-input');
    if (portInput && parsed.port) portInput.value = parsed.port;
  } catch {}

  // Also pre-fill the sitemap target input
  setSitemapTarget(url);
}

/**
 * Open the Scanner panel and pre-fill a URL target.
 * Called from hostDetails.js via window.__openScannerPanel(url).
 */
export function openInScanner(url) {
  const webappTab = document.querySelector('.workspace-tab[data-workspace="webapp"]');
  webappTab?.click();

  const scannerItem = document.querySelector('#webapp-sidebar .sidebar-item[data-panel="scanner"]');
  scannerItem?.click();

  scanUrl(url);
}

/**
 * Open the Repeater panel with a pre-filled request.
 * Called from proxy history context-menu "Send to Repeater".
 */
export function openInRepeater(rawRequest, label, targetUrl) {
  const webappTab = document.querySelector('.workspace-tab[data-workspace="webapp"]');
  webappTab?.click();
  openRepeaterTab(rawRequest ?? '', label ?? null, targetUrl ?? '');
}

/**
 * Open the Intruder panel with a pre-filled request template.
 */
export function openInIntruder(rawRequest, targetUrl) {
  const webappTab = document.querySelector('.workspace-tab[data-workspace="webapp"]');
  webappTab?.click();
  openIntruderWith(rawRequest ?? '', targetUrl ?? '');
}

// ─── Boot ─────────────────────────────────────────────────────────────────────

export function init() {
  _initWorkspaceSwitcher();
  _initSidebar();
  initProxy();
  initSitemap();
  initScanner();
  initRepeater();
  initIntruder();
  initSequencer();
  initDecoder();
  initComparer();

  // Expose pivot functions globally for cross-workspace integration
  window.__openWebAppWorkspace = openInWebApp;
  window.__openScannerPanel    = openInScanner;
  window.__openRepeaterPanel   = openInRepeater;
  window.__openIntruderPanel   = openInIntruder;
}
