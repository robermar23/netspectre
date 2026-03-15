/**
 * webapp/index.js — Web App Workspace Orchestrator
 * Bootstraps the workspace-switcher, sidebar navigation,
 * and all sub-module inits for Feature 7.
 */

import { state } from '../../state.js';
import { init as initProxy } from './proxy.js';
import { init as initSitemap, setTargetUrl as setSitemapTarget } from './sitemap.js';
import { init as initScanner, scanUrl } from './scanner.js';

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

// ─── Boot ─────────────────────────────────────────────────────────────────────

export function init() {
  _initWorkspaceSwitcher();
  _initSidebar();
  initProxy();
  initSitemap();
  initScanner();

  // Expose pivot functions globally for hostDetails / Network workspace integration
  window.__openWebAppWorkspace = openInWebApp;
  window.__openScannerPanel    = openInScanner;
}
