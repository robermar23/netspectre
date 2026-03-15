import { elements } from '../ui.js';
import { api } from '../api.js';

// Settings DOM elements
const btnSettings = document.getElementById('btn-settings');
const settingsModalOverlay = document.getElementById('settings-modal-overlay');
const btnCloseSettingsModal = document.getElementById('btn-close-settings-modal');
const btnSettingsDone = document.getElementById('btn-settings-done');

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
const statusPlaywright = document.getElementById('status-playwright');

const vlanPanel = document.getElementById('vlan-panel');

async function syncDependencyToggle({
  checkFn,
  installedText,
  missingText,
  statusEl,
  settingsKey,
  toggleEl,
}) {
  const settings = await api.settings.getAll();
  const pathInputEl = document.getElementById(`setting-path-${settingsKey}`);
  if (pathInputEl) {
    pathInputEl.value = settings[settingsKey]?.path || '';
  }

  const { installed } = await checkFn();
  const statusText = statusEl.querySelector('.status-text');

  statusEl.classList.toggle('installed', installed);
  statusEl.classList.toggle('missing', !installed);
  if (statusText) {
    statusText.textContent = installed ? installedText : missingText;
  }

  const enabled = settings[settingsKey]?.enabled !== false;

  toggleEl.checked = enabled;
  if (!installed && enabled) {
    toggleEl.checked = false;
    toggleEl.disabled = true;
    await api.settings.set(`${settingsKey}.enabled`, false);
  }

  return { installed, enabled };
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

  // Playwright — npm package, no toggle or path override
  if (statusPlaywright) {
    const { installed, installPath, isPackaged } = await api.crawler.checkPlaywright();
    statusPlaywright.classList.toggle('installed', installed);
    statusPlaywright.classList.toggle('missing', !installed);
    const pwText = statusPlaywright.querySelector('.status-text');
    if (pwText) {
      pwText.textContent = installed
        ? 'playwright-core installed — Active crawl ready'
        : 'Not installed';
    }

    const stepsEl = document.getElementById('playwright-install-steps');
    if (stepsEl) {
      stepsEl.style.display = installed ? 'none' : 'block';
      if (!installed && installPath) {
        const cdCmd = document.querySelector('#playwright-cmd-cd .install-cmd-text');
        if (cdCmd) cdCmd.textContent = `cd "${installPath}"`;

        // Add a context note for packaged installs so the path is less surprising
        const noteEl = document.getElementById('playwright-path-note');
        if (noteEl) {
          noteEl.textContent = isPackaged
            ? 'This is your NetSpectre data directory — the only writable location in a packaged install.'
            : 'This is the NetSpectre development directory.';
        }
      }
    }
  }

  applySettingsUI(settings);
}

export function init() {
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

  // Handle manual path overrides
  document.querySelectorAll('.custom-path-input').forEach(input => {
    input.addEventListener('change', async (e) => {
      const targetKey = e.target.id.replace('setting-path-', '');
      await api.settings.set(`${targetKey}.path`, e.target.value.trim());
      loadAndApplySettings(); // Re-trigger dependency checks
    });
  });

  // Handle file browse dialogs for paths
  document.querySelectorAll('.btn-browse-path').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const targetInputId = e.currentTarget.getAttribute('data-target');
      const inputEl = document.getElementById(targetInputId);
      const targetKey = targetInputId.replace('setting-path-', '');

      const result = await window.electronAPI.browseFile({
        title: `Select ${targetKey} Executable`,
        properties: ['openFile'],
        filters: [{ name: 'Executables', extensions: ['exe', 'bat', 'cmd', 'sh', '*'] }]
      });

      if (!result.canceled && result.filePaths.length > 0) {
        const selectedPath = result.filePaths[0];
        inputEl.value = selectedPath;
        await api.settings.set(`${targetKey}.path`, selectedPath);
        loadAndApplySettings(); // Re-trigger dependency checks
      }
    });
  });

  // Copy buttons for install command rows
  document.querySelectorAll('.btn-copy-cmd').forEach(btn => {
    btn.addEventListener('click', () => {
      const text = btn.previousElementSibling?.textContent?.trim();
      if (text) {
        navigator.clipboard.writeText(text).then(() => {
          const orig = btn.textContent;
          btn.textContent = '✓';
          setTimeout(() => { btn.textContent = orig; }, 1500);
        });
      }
    });
  });

  // Run once on boot
  loadAndApplySettings();
}

export { applySettingsUI };
