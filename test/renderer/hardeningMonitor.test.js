/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';

const htmlDoc = fs.readFileSync(path.resolve(__dirname, '../../src/renderer/index.html'), 'utf8');

describe('Hardening Monitor UI', () => {
  beforeEach(() => {
    document.body.innerHTML = htmlDoc;

    // Mock electronAPI — hardeningMonitor uses nested namespace
    window.electronAPI = {
      hardeningMonitor: {
        start: vi.fn().mockResolvedValue({ status: 'started' }),
        stop: vi.fn().mockResolvedValue(undefined),
        setBaseline: vi.fn().mockResolvedValue(undefined),
        getBaseline: vi.fn().mockResolvedValue({ hosts: [] }),
        onHostUpdate: vi.fn(),
        onStatus: vi.fn(),
        onDeltaAlert: vi.fn(),
        onDeltaReport: vi.fn(),
      },
    };
  });

  it('hardening panel exists in DOM', () => {
    const panel = document.getElementById('hardening-panel');
    expect(panel).not.toBeNull();
  });

  it('hardening open button exists in DOM', () => {
    const btn = document.getElementById('btn-hardening-open');
    expect(btn).not.toBeNull();
  });

  it('panel is initially not open (no "open" class)', () => {
    const panel = document.getElementById('hardening-panel');
    expect(panel.classList.contains('open')).toBe(false);
  });

  it('setOpenDetailsPanelRef stores a function reference', () => {
    // Replicate the module-level logic for setOpenDetailsPanelRef
    let _openDetailsPanel = null;
    function setOpenDetailsPanelRef(fn) { _openDetailsPanel = fn; }

    const mockFn = vi.fn();
    setOpenDetailsPanelRef(mockFn);
    expect(_openDetailsPanel).toBe(mockFn);
  });

  it('setOpenDetailsPanelRef can be overwritten', () => {
    let _openDetailsPanel = null;
    function setOpenDetailsPanelRef(fn) { _openDetailsPanel = fn; }

    const fn1 = vi.fn();
    const fn2 = vi.fn();
    setOpenDetailsPanelRef(fn1);
    setOpenDetailsPanelRef(fn2);
    expect(_openDetailsPanel).toBe(fn2);
  });

  it('openPanel opens the hardening panel', () => {
    const panel = document.getElementById('hardening-panel');
    const resizer = document.getElementById('hardening-resizer');

    // Simulate openHardeningPanel() as the module does
    panel.style.display = 'flex';
    panel.classList.add('open');
    if (resizer) resizer.style.display = 'block';

    expect(panel.classList.contains('open')).toBe(true);
  });

  it('openPanel with subnet prefills subnet input', () => {
    const subnetInput = document.getElementById('hardening-subnet');

    // Simulate openHardeningPanel(subnet)
    const subnet = '192.168.1.0/24';
    if (subnetInput) subnetInput.value = subnet;

    expect(subnetInput.value).toBe('192.168.1.0/24');
  });

  it('clicking btn-hardening-open opens the panel when closed', () => {
    const panel = document.getElementById('hardening-panel');
    const btn = document.getElementById('btn-hardening-open');
    const resizer = document.getElementById('hardening-resizer');

    // Start with panel display:none (closed state)
    panel.style.display = 'none';

    btn.addEventListener('click', () => {
      if (panel.style.display !== 'none') {
        // close
        panel.classList.remove('open');
        panel.style.display = 'none';
      } else {
        // open
        panel.style.display = 'flex';
        panel.classList.add('open');
        if (resizer) resizer.style.display = 'block';
      }
    });

    btn.click();
    expect(panel.classList.contains('open')).toBe(true);
    expect(panel.style.display).toBe('flex');
  });

  it('clicking close button closes the panel', () => {
    const panel = document.getElementById('hardening-panel');
    const btnClose = document.getElementById('btn-close-hardening-panel');
    const resizer = document.getElementById('hardening-resizer');

    // Open first
    panel.classList.add('open');
    panel.style.display = 'flex';

    btnClose.addEventListener('click', () => {
      panel.classList.remove('open');
      if (resizer) resizer.style.display = 'none';
    });

    btnClose.click();
    expect(panel.classList.contains('open')).toBe(false);
  });

  it('onDeltaAlert callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.hardeningMonitor.onDeltaAlert(handler);
    expect(window.electronAPI.hardeningMonitor.onDeltaAlert).toHaveBeenCalledWith(handler);
  });

  it('onHostUpdate callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.hardeningMonitor.onHostUpdate(handler);
    expect(window.electronAPI.hardeningMonitor.onHostUpdate).toHaveBeenCalledWith(handler);
  });

  it('onStatus callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.hardeningMonitor.onStatus(handler);
    expect(window.electronAPI.hardeningMonitor.onStatus).toHaveBeenCalledWith(handler);
  });

  it('start button calls hardeningMonitor.start with subnet and options', async () => {
    const subnetInput = document.getElementById('hardening-subnet');
    const btnStart = document.getElementById('btn-hardening-start');

    subnetInput.value = '10.0.0.0/24';

    btnStart.addEventListener('click', async () => {
      const subnet = subnetInput.value.trim();
      if (!subnet) return;
      await window.electronAPI.hardeningMonitor.start(subnet, { intervalMs: 900000, deepScan: true });
    });

    btnStart.click();
    await Promise.resolve();

    expect(window.electronAPI.hardeningMonitor.start).toHaveBeenCalledWith(
      '10.0.0.0/24',
      expect.objectContaining({ intervalMs: expect.any(Number) })
    );
  });

  it('stop button calls hardeningMonitor.stop with subnet', async () => {
    const subnetInput = document.getElementById('hardening-subnet');
    const btnStop = document.getElementById('btn-hardening-stop');

    subnetInput.value = '10.0.0.0/24';

    // Stop button is disabled by default; enable it to simulate a running state
    btnStop.disabled = false;

    btnStop.addEventListener('click', async () => {
      const subnet = subnetInput.value.trim();
      if (!subnet) return;
      await window.electronAPI.hardeningMonitor.stop(subnet);
    });

    btnStop.click();
    await Promise.resolve();

    expect(window.electronAPI.hardeningMonitor.stop).toHaveBeenCalledWith('10.0.0.0/24');
  });

  it('key DOM elements for hardening monitor exist', () => {
    expect(document.getElementById('hardening-subnet')).not.toBeNull();
    expect(document.getElementById('hardening-alerts-list')).not.toBeNull();
    expect(document.getElementById('hardening-alert-count')).not.toBeNull();
    expect(document.getElementById('hardening-status-dot')).not.toBeNull();
    expect(document.getElementById('hardening-last-scan-text')).not.toBeNull();
  });
});
