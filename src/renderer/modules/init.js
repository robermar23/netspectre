import { elements } from '../ui.js';
import { api } from '../api.js';
import { state } from '../state.js';

/**
 * Dependency checks, banner display, CSS class toggling for tool availability.
 * Returns { deps } — the dependency check results.
 */
export async function init() {
  const [isNmapInstalled, tsharkStatus, hydraStatus, msfrpcdStatus, smbclientStatus] = await Promise.all([
    api.checkNmap(),
    api.settings.checkDependency('tshark'),
    api.settings.checkDependency('hydra'),
    api.settings.checkDependency('msfrpcd'),
    api.settings.checkDependency('smbclient'),
  ]);

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

  if (elements.btnCloseNmapBanner) {
    elements.btnCloseNmapBanner.addEventListener('click', () => {
      if (elements.nmapInstallBanner) elements.nmapInstallBanner.style.display = 'none';
    });
  }

  const deps = {
    isNmapInstalled,
    isTsharkInstalled,
    isHydraInstalled,
    isMsfrpcdInstalled,
    isSmbclientInstalled,
  };

  return { deps };
}
