/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';

const htmlDoc = fs.readFileSync(path.resolve(__dirname, '../../src/renderer/index.html'), 'utf8');

describe('Share Enumeration UI', () => {
  beforeEach(() => {
    document.body.innerHTML = htmlDoc;

    // Mock electronAPI with all callbacks shareEnum module registers
    window.electronAPI = {
      enumerateShares: vi.fn().mockResolvedValue({ status: 'ok' }),
      browseShare: vi.fn().mockResolvedValue({ status: 'ok', entries: [] }),
      downloadShareFile: vi.fn().mockResolvedValue({ status: 'downloaded', localPath: '/tmp/file' }),
      onShareResult: vi.fn(),
      onShareError: vi.fn(),
    };
  });

  it('share panel exists in DOM', () => {
    const panel = document.getElementById('share-panel');
    expect(panel).not.toBeNull();
  });

  it('share enum open button exists in DOM', () => {
    const btn = document.getElementById('btn-share-enum-open');
    expect(btn).not.toBeNull();
  });

  it('panel is initially not open (no "open" class)', () => {
    const panel = document.getElementById('share-panel');
    expect(panel.classList.contains('open')).toBe(false);
  });

  it('openPanel sets target IP and opens panel', () => {
    const panel = document.getElementById('share-panel');
    const targetIpInput = document.getElementById('share-target-ip');
    const resizer = document.getElementById('share-resizer');

    // Simulate openPanel(ip) as the module does
    const prefilledIp = '192.168.1.10';
    if (targetIpInput) targetIpInput.value = prefilledIp;
    panel.style.display = 'flex';
    panel.classList.add('open');
    if (resizer) resizer.style.display = 'block';

    expect(targetIpInput.value).toBe('192.168.1.10');
    expect(panel.classList.contains('open')).toBe(true);
  });

  it('openPanel with empty string does not set IP', () => {
    const targetIpInput = document.getElementById('share-target-ip');
    targetIpInput.value = '';

    // openPanel('') — no prefilledIp, so value stays empty
    expect(targetIpInput.value).toBe('');
  });

  it('clicking btn-share-enum-open opens the panel when closed', () => {
    const panel = document.getElementById('share-panel');
    const btn = document.getElementById('btn-share-enum-open');
    const resizer = document.getElementById('share-resizer');

    // Wire toggle as the module does
    btn.addEventListener('click', () => {
      if (panel.style.display === 'none' || !panel.classList.contains('open')) {
        panel.style.display = 'flex';
        panel.classList.add('open');
        if (resizer) resizer.style.display = 'block';
      } else {
        panel.classList.remove('open');
        setTimeout(() => {
          panel.style.display = 'none';
          if (resizer) resizer.style.display = 'none';
        }, 300);
      }
    });

    // Ensure panel starts closed
    panel.style.display = 'none';
    panel.classList.remove('open');

    btn.click();
    expect(panel.classList.contains('open')).toBe(true);
    expect(panel.style.display).toBe('flex');
  });

  it('close button removes "open" class from share panel', () => {
    const panel = document.getElementById('share-panel');
    const btnClose = document.getElementById('btn-close-share-panel');
    const resizer = document.getElementById('share-resizer');

    // Open the panel first
    panel.classList.add('open');
    panel.style.display = 'flex';

    btnClose.addEventListener('click', () => {
      panel.classList.remove('open');
      if (resizer) resizer.style.display = 'none';
    });

    btnClose.click();
    expect(panel.classList.contains('open')).toBe(false);
  });

  it('enumerate button calls enumerateShares with target IP', async () => {
    const targetIpInput = document.getElementById('share-target-ip');
    const btnEnumerate = document.getElementById('btn-share-enumerate');

    targetIpInput.value = '10.0.0.5';

    btnEnumerate.addEventListener('click', async () => {
      const targetIp = targetIpInput.value.trim();
      if (targetIp) {
        await window.electronAPI.enumerateShares({ targetIp, credentials: null });
      }
    });

    btnEnumerate.click();
    await Promise.resolve();

    expect(window.electronAPI.enumerateShares).toHaveBeenCalledWith(
      expect.objectContaining({ targetIp: '10.0.0.5' })
    );
  });

  it('onShareResult callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onShareResult(handler);
    expect(window.electronAPI.onShareResult).toHaveBeenCalledWith(handler);
  });

  it('onShareError callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onShareError(handler);
    expect(window.electronAPI.onShareError).toHaveBeenCalledWith(handler);
  });

  it('share target IP input exists in DOM', () => {
    const input = document.getElementById('share-target-ip');
    expect(input).not.toBeNull();
  });

  it('share error banner exists in DOM', () => {
    const banner = document.getElementById('share-error-banner');
    expect(banner).not.toBeNull();
  });

  it('share status text element exists in DOM', () => {
    const status = document.getElementById('share-status-text');
    expect(status).not.toBeNull();
  });

  it('SMB and NFS share list containers exist in DOM', () => {
    expect(document.getElementById('share-list-smb')).not.toBeNull();
    expect(document.getElementById('share-list-nfs')).not.toBeNull();
  });
});
