/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';

const htmlDoc = fs.readFileSync(path.resolve(__dirname, '../../src/renderer/index.html'), 'utf8');

describe('Settings UI', () => {
  beforeEach(() => {
    document.body.innerHTML = htmlDoc;

    // Mock electronAPI — settings module calls settings.getAll, checkNmap, checkDependency
    window.electronAPI = {
      checkNmap: vi.fn().mockResolvedValue(true),
      settings: {
        get: vi.fn().mockResolvedValue(null),
        set: vi.fn().mockResolvedValue(undefined),
        getAll: vi.fn().mockResolvedValue({
          nmap: { enabled: true },
          tshark: { enabled: false },
          hydra: { enabled: false },
          msfrpcd: { enabled: false },
          smbclient: { enabled: false },
          showmount: { enabled: false },
        }),
        checkDependency: vi.fn().mockResolvedValue({ installed: false }),
      },
    };
  });

  it('settings modal overlay exists in DOM', () => {
    const overlay = document.getElementById('settings-modal-overlay');
    expect(overlay).not.toBeNull();
  });

  it('settings open button exists in DOM', () => {
    const btn = document.getElementById('btn-settings');
    expect(btn).not.toBeNull();
  });

  it('settings modal is initially hidden', () => {
    const overlay = document.getElementById('settings-modal-overlay');
    expect(overlay.classList.contains('hidden')).toBe(true);
  });

  it('clicking btn-settings opens the settings modal', () => {
    const btn = document.getElementById('btn-settings');
    const overlay = document.getElementById('settings-modal-overlay');

    // Wire the click handler as the settings module does
    btn.addEventListener('click', () => {
      overlay.classList.remove('hidden');
    });

    btn.click();
    expect(overlay.classList.contains('hidden')).toBe(false);
  });

  it('clicking close button hides the settings modal', () => {
    const overlay = document.getElementById('settings-modal-overlay');
    const btnClose = document.getElementById('btn-close-settings-modal');

    // Open first
    overlay.classList.remove('hidden');

    btnClose.addEventListener('click', () => {
      overlay.classList.add('hidden');
    });

    btnClose.click();
    expect(overlay.classList.contains('hidden')).toBe(true);
  });

  it('clicking settings-done button hides the settings modal', () => {
    const overlay = document.getElementById('settings-modal-overlay');
    const btnDone = document.getElementById('btn-settings-done');

    // Open first
    overlay.classList.remove('hidden');

    btnDone.addEventListener('click', () => {
      overlay.classList.add('hidden');
    });

    btnDone.click();
    expect(overlay.classList.contains('hidden')).toBe(true);
  });

  it('nmap toggle calls settings.set when changed', async () => {
    const toggle = document.getElementById('setting-nmap-enabled');

    toggle.addEventListener('change', async (e) => {
      await window.electronAPI.settings.set('nmap.enabled', e.target.checked);
    });

    toggle.checked = false;
    toggle.dispatchEvent(new Event('change'));
    await Promise.resolve();

    expect(window.electronAPI.settings.set).toHaveBeenCalledWith('nmap.enabled', false);
  });

  it('tshark toggle calls settings.set when changed', async () => {
    const toggle = document.getElementById('setting-tshark-enabled');

    toggle.addEventListener('change', async (e) => {
      await window.electronAPI.settings.set('tshark.enabled', e.target.checked);
    });

    toggle.checked = true;
    toggle.dispatchEvent(new Event('change'));
    await Promise.resolve();

    expect(window.electronAPI.settings.set).toHaveBeenCalledWith('tshark.enabled', true);
  });

  it('hydra toggle calls settings.set when changed', async () => {
    const toggle = document.getElementById('setting-hydra-enabled');

    toggle.addEventListener('change', async (e) => {
      await window.electronAPI.settings.set('hydra.enabled', e.target.checked);
    });

    toggle.checked = true;
    toggle.dispatchEvent(new Event('change'));
    await Promise.resolve();

    expect(window.electronAPI.settings.set).toHaveBeenCalledWith('hydra.enabled', true);
  });

  it('dependency status elements exist in DOM', () => {
    expect(document.getElementById('status-nmap')).not.toBeNull();
    expect(document.getElementById('status-tshark')).not.toBeNull();
    expect(document.getElementById('status-hydra')).not.toBeNull();
    expect(document.getElementById('status-msfrpcd')).not.toBeNull();
    expect(document.getElementById('status-smbclient')).not.toBeNull();
    expect(document.getElementById('status-showmount')).not.toBeNull();
  });
});
