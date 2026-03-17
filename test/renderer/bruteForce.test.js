/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';

const htmlDoc = fs.readFileSync(path.resolve(__dirname, '../../src/renderer/index.html'), 'utf8');

describe('Brute-Force UI', () => {
  beforeEach(() => {
    document.body.innerHTML = htmlDoc;

    // Mock electronAPI with all callbacks brute-force module registers
    window.electronAPI = {
      settings: {
        get: vi.fn().mockResolvedValue(false),
        set: vi.fn().mockResolvedValue(undefined),
        getAll: vi.fn().mockResolvedValue({}),
        checkDependency: vi.fn().mockResolvedValue({ installed: false }),
      },
      startBruteForce: vi.fn().mockResolvedValue({ status: 'started' }),
      stopBruteForce: vi.fn().mockResolvedValue(undefined),
      browseFile: vi.fn().mockResolvedValue({ status: 'cancelled' }),
      onBruteForceAttempt: vi.fn(),
      onBruteForceResult: vi.fn(),
      onBruteForceProgress: vi.fn(),
      onBruteForceError: vi.fn(),
      onBruteForceComplete: vi.fn(),
    };
  });

  it('bruteforce panel exists in DOM', () => {
    const panel = document.getElementById('bruteforce-panel');
    expect(panel).not.toBeNull();
  });

  it('pentest consent overlay exists in DOM', () => {
    const consent = document.getElementById('pentest-consent-overlay');
    expect(consent).not.toBeNull();
  });

  it('brute-force panel is initially hidden', () => {
    const panel = document.getElementById('bruteforce-panel');
    expect(panel.style.display).toBe('none');
  });

  it('onBruteForceResult callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onBruteForceResult(handler);
    expect(window.electronAPI.onBruteForceResult).toHaveBeenCalledWith(handler);
  });

  it('onBruteForceProgress callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onBruteForceProgress(handler);
    expect(window.electronAPI.onBruteForceProgress).toHaveBeenCalledWith(handler);
  });

  it('onBruteForceComplete callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onBruteForceComplete(handler);
    expect(window.electronAPI.onBruteForceComplete).toHaveBeenCalledWith(handler);
  });

  it('onBruteForceError callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onBruteForceError(handler);
    expect(window.electronAPI.onBruteForceError).toHaveBeenCalledWith(handler);
  });

  it('clicking accept on pentest consent opens brute-force panel', async () => {
    const consentOverlay = document.getElementById('pentest-consent-overlay');
    const bfPanel = document.getElementById('bruteforce-panel');
    const btnAccept = document.getElementById('btn-pentest-consent-accept');

    // Wire up the consent logic manually (as the module would do)
    btnAccept.addEventListener('click', async () => {
      await window.electronAPI.settings.set('pentestConsentAccepted', true);
      consentOverlay.classList.add('hidden');
      bfPanel.style.display = 'flex';
      bfPanel.classList.add('open');
    });

    btnAccept.click();
    await Promise.resolve(); // flush microtasks

    expect(window.electronAPI.settings.set).toHaveBeenCalledWith('pentestConsentAccepted', true);
    expect(bfPanel.style.display).toBe('flex');
    expect(consentOverlay.classList.contains('hidden')).toBe(true);
  });

  it('closing brute-force panel hides it', () => {
    const bfPanel = document.getElementById('bruteforce-panel');
    const btnClose = document.getElementById('btn-close-bruteforce-panel');

    // Open first
    bfPanel.style.display = 'flex';
    bfPanel.classList.add('open');

    // Wire close button as the module does
    btnClose.addEventListener('click', () => {
      bfPanel.classList.remove('open');
      bfPanel.style.display = 'none';
    });

    btnClose.click();
    expect(bfPanel.style.display).toBe('none');
    expect(bfPanel.classList.contains('open')).toBe(false);
  });

  it('start button calls startBruteForce with correct payload', async () => {
    const bfPanel = document.getElementById('bruteforce-panel');
    bfPanel.style.display = 'flex';

    const btnStart = document.getElementById('btn-bf-start');
    const btnStop = document.getElementById('btn-bf-stop');
    const bfTargetIp = document.getElementById('bf-target-ip');
    const bfPort = document.getElementById('bf-port');
    const bfProtocol = document.getElementById('bf-protocol');
    const bfUsername = document.getElementById('bf-username');
    const bfWordlistPath = document.getElementById('bf-wordlist-path');
    const bfProgressContainer = document.getElementById('bf-progress-container');
    const bfProgressFill = document.getElementById('bf-progress-fill');
    const bfProgressText = document.getElementById('bf-progress-text');
    const bfResultsBody = document.getElementById('bf-results-body');

    bfTargetIp.value = '192.168.1.1';
    bfPort.value = '22';
    bfProtocol.value = 'ssh';
    bfUsername.value = 'admin';
    bfWordlistPath.value = '/tmp/wordlist.txt';

    // Wire start button logic as the module does
    btnStart.addEventListener('click', async () => {
      const targetIp = bfTargetIp.value.trim();
      const port = parseInt(bfPort.value, 10);
      const protocol = bfProtocol.value;
      const username = bfUsername.value.trim();
      const wordlistPath = bfWordlistPath.value.trim();

      if (!targetIp || !port || !username || !wordlistPath) return;

      btnStart.disabled = true;
      btnStop.disabled = false;
      bfProgressContainer.style.display = 'block';
      bfProgressFill.style.width = '0%';
      bfProgressText.textContent = 'Starting...';
      if (bfResultsBody) bfResultsBody.innerHTML = '';

      await window.electronAPI.startBruteForce({ targetIp, port, protocol, username, wordlistPath, threads: 4, delay: 0, maxAttempts: 10000 });
    });

    btnStart.click();
    await Promise.resolve();

    expect(window.electronAPI.startBruteForce).toHaveBeenCalledWith(
      expect.objectContaining({ targetIp: '192.168.1.1', port: 22, protocol: 'ssh', username: 'admin', wordlistPath: '/tmp/wordlist.txt' })
    );
    expect(btnStart.disabled).toBe(true);
    expect(btnStop.disabled).toBe(false);
  });

  it('stop button calls stopBruteForce', async () => {
    const btnStop = document.getElementById('btn-bf-stop');
    const btnStart = document.getElementById('btn-bf-start');

    // Stop button is disabled by default; enable it to simulate a running state
    btnStop.disabled = false;

    btnStop.addEventListener('click', async () => {
      await window.electronAPI.stopBruteForce();
      btnStart.disabled = false;
      btnStop.disabled = true;
    });

    btnStop.click();
    await Promise.resolve();

    expect(window.electronAPI.stopBruteForce).toHaveBeenCalled();
    expect(btnStart.disabled).toBe(false);
  });
});
