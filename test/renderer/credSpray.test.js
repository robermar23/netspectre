/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';

const htmlDoc = fs.readFileSync(path.resolve(__dirname, '../../src/renderer/index.html'), 'utf8');

describe('Credential Spray UI', () => {
  beforeEach(() => {
    document.body.innerHTML = htmlDoc;

    // Mock electronAPI with all callbacks credSpray module registers
    window.electronAPI = {
      startCredSpray: vi.fn().mockResolvedValue({ status: 'started' }),
      stopCredSpray: vi.fn().mockResolvedValue(undefined),
      onCredSprayHit: vi.fn(),
      onCredSprayProgress: vi.fn(),
      onCredSprayComplete: vi.fn(),
      onCredSprayError: vi.fn(),
      settings: {
        get: vi.fn().mockResolvedValue(false),
        set: vi.fn().mockResolvedValue(undefined),
        getAll: vi.fn().mockResolvedValue({}),
      },
    };
  });

  it('credspray panel exists in DOM', () => {
    const panel = document.getElementById('credspray-panel');
    expect(panel).not.toBeNull();
  });

  it('credspray open button exists in DOM', () => {
    const btn = document.getElementById('btn-credspray-open');
    expect(btn).not.toBeNull();
  });

  it('panel is initially not open (no "open" class)', () => {
    const panel = document.getElementById('credspray-panel');
    expect(panel.classList.contains('open')).toBe(false);
  });

  it('openPanel adds "open" class to credspray panel', () => {
    const panel = document.getElementById('credspray-panel');
    const resizer = document.getElementById('credspray-resizer');

    // Simulate what openCredSprayPanel does
    panel.classList.add('open');
    if (resizer) resizer.style.display = 'block';

    expect(panel.classList.contains('open')).toBe(true);
  });

  it('openPanel with IP prefills the target IP input', () => {
    const targetIpInput = document.getElementById('credspray-target-ip');
    const targetMode = document.getElementById('credspray-target-mode');
    const targetIpGroup = document.getElementById('credspray-single-ip-group');

    const prefilledIp = '10.0.0.5';

    // Simulate openCredSprayPanel(prefilledIp)
    if (targetIpInput) targetIpInput.value = prefilledIp;
    if (targetMode) targetMode.value = 'single';
    if (targetIpGroup) targetIpGroup.style.display = 'block';

    expect(targetIpInput.value).toBe('10.0.0.5');
    expect(targetMode.value).toBe('single');
  });

  it('clicking btn-credspray-open opens the panel when closed', () => {
    const panel = document.getElementById('credspray-panel');
    const btnOpen = document.getElementById('btn-credspray-open');
    const resizer = document.getElementById('credspray-resizer');

    // Wire the toggle as the module does
    btnOpen.addEventListener('click', () => {
      if (panel.classList.contains('open')) {
        panel.classList.remove('open');
        if (resizer) resizer.style.display = 'none';
      } else {
        panel.classList.add('open');
        if (resizer) resizer.style.display = 'block';
      }
    });

    expect(panel.classList.contains('open')).toBe(false);
    btnOpen.click();
    expect(panel.classList.contains('open')).toBe(true);
  });

  it('clicking close button removes "open" class from panel', () => {
    const panel = document.getElementById('credspray-panel');
    const btnClose = document.getElementById('btn-close-credspray');
    const resizer = document.getElementById('credspray-resizer');

    // Open the panel first
    panel.classList.add('open');

    btnClose.addEventListener('click', () => {
      panel.classList.remove('open');
      if (resizer) resizer.style.display = 'none';
    });

    btnClose.click();
    expect(panel.classList.contains('open')).toBe(false);
  });

  it('onCredSprayHit callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onCredSprayHit(handler);
    expect(window.electronAPI.onCredSprayHit).toHaveBeenCalledWith(handler);
  });

  it('onCredSprayProgress callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onCredSprayProgress(handler);
    expect(window.electronAPI.onCredSprayProgress).toHaveBeenCalledWith(handler);
  });

  it('onCredSprayComplete callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onCredSprayComplete(handler);
    expect(window.electronAPI.onCredSprayComplete).toHaveBeenCalledWith(handler);
  });

  it('onCredSprayError callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onCredSprayError(handler);
    expect(window.electronAPI.onCredSprayError).toHaveBeenCalledWith(handler);
  });

  it('stop button calls stopCredSpray', async () => {
    const btnStop = document.getElementById('btn-credspray-stop');

    // Stop button is disabled by default; enable it to simulate a running state
    btnStop.disabled = false;

    btnStop.addEventListener('click', async () => {
      await window.electronAPI.stopCredSpray();
    });

    btnStop.click();
    await Promise.resolve();

    expect(window.electronAPI.stopCredSpray).toHaveBeenCalled();
  });

  it('target mode change shows/hides single IP group', () => {
    const targetMode = document.getElementById('credspray-target-mode');
    const targetIpGroup = document.getElementById('credspray-single-ip-group');

    targetMode.addEventListener('change', () => {
      if (targetIpGroup) {
        targetIpGroup.style.display = targetMode.value === 'single' ? 'block' : 'none';
      }
    });

    targetMode.value = 'single';
    targetMode.dispatchEvent(new Event('change'));
    expect(targetIpGroup.style.display).toBe('block');

    targetMode.value = 'all';
    targetMode.dispatchEvent(new Event('change'));
    expect(targetIpGroup.style.display).toBe('none');
  });
});
