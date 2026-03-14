/**
 * @vitest-environment jsdom
 * Feature 5C — Container & Cloud Enumeration — Renderer UI Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs   from 'fs';
import path from 'path';

// ─── Module mocks (hoisted before imports) ────────────────────────────────────

vi.mock('../../src/renderer/api.js', () => ({
  api: {
    cloudEnum: {
      start: vi.fn().mockResolvedValue({ status: 'started' }),
      stop:  vi.fn().mockResolvedValue({ status: 'stopped' }),
    },
  },
}));

vi.mock('../../src/renderer/state.js', () => ({
  state: {
    hosts: [],
    isCloudEnumRunning: false,
    cloudFindings: [],
  },
}));

import { init }  from '../../src/renderer/modules/cloudEnum.js';
import { api }   from '../../src/renderer/api.js';
import { state } from '../../src/renderer/state.js';

const htmlDoc = fs.readFileSync(path.resolve(__dirname, '../../src/renderer/index.html'), 'utf8');

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Flush pending microtasks / resolved promises. */
const flush = () => new Promise(r => setTimeout(r, 0));

/** Returns the callback registered with a mock IPC listener after init(). */
function captureIpcCb(mockFn) {
  return mockFn.mock.calls[0]?.[0];
}

// ─── Test setup ───────────────────────────────────────────────────────────────

describe('Cloud Enum UI', () => {
  beforeEach(() => {
    document.body.innerHTML = htmlDoc;

    // Reset shared state between tests
    state.hosts              = [{ ip: '192.168.1.1' }];
    state.isCloudEnumRunning = false;
    state.cloudFindings      = [];

    // Reset api mocks
    api.cloudEnum.start.mockClear();
    api.cloudEnum.start.mockResolvedValue({ status: 'started' });
    api.cloudEnum.stop.mockClear();

    // Provide electronAPI with vi.fn() listeners so init() can register callbacks
    window.electronAPI = {
      cloudEnum: {
        start:      vi.fn().mockResolvedValue({ status: 'started' }),
        stop:       vi.fn().mockResolvedValue({ status: 'stopped' }),
        onFinding:  vi.fn(),
        onProgress: vi.fn(),
        onComplete: vi.fn(),
        onError:    vi.fn(),
      },
    };

    init();
  });

  // ─── Static DOM tests (existing) ──────────────────────────────────────────

  it('cloudenum panel exists in DOM', () => {
    expect(document.getElementById('cloudenum-panel')).not.toBeNull();
  });

  it('cloud enum open button exists in header', () => {
    expect(document.getElementById('btn-cloudenum-open')).not.toBeNull();
  });

  it('close button exists inside the panel', () => {
    expect(document.getElementById('btn-close-cloudenum-panel')).not.toBeNull();
  });

  it('panel is initially hidden (display:none)', () => {
    const panel = document.getElementById('cloudenum-panel');
    expect(panel.style.display).toBe('none');
  });

  it('start and stop buttons exist', () => {
    expect(document.getElementById('btn-cloudenum-start')).not.toBeNull();
    expect(document.getElementById('btn-cloudenum-stop')).not.toBeNull();
  });

  it('stop button is initially disabled', () => {
    const btnStop = document.getElementById('btn-cloudenum-stop');
    expect(btnStop.disabled).toBe(true);
  });

  it('export button is initially disabled', () => {
    const btnExport = document.getElementById('btn-cloudenum-export');
    expect(btnExport.disabled).toBe(true);
  });

  it('target mode select defaults to all-hosts', () => {
    const sel = document.getElementById('cloudenum-target-mode');
    expect(sel).not.toBeNull();
    expect(sel.value).toBe('all');
  });

  it('single-host IP group is initially hidden', () => {
    const grp = document.getElementById('cloudenum-single-ip-group');
    expect(grp.style.display).toBe('none');
  });

  it('all seven probe checkboxes are present and checked by default', () => {
    const cbs = document.querySelectorAll('.cloudenum-probe-cb');
    expect(cbs.length).toBe(7);
    cbs.forEach(cb => expect(cb.checked).toBe(true));
  });

  it('concurrency slider exists with default value 10', () => {
    const slider = document.getElementById('cloudenum-concurrency');
    expect(slider).not.toBeNull();
    expect(slider.value).toBe('10');
  });

  it('progress container is initially hidden', () => {
    const container = document.getElementById('cloudenum-progress-container');
    expect(container.style.display).toBe('none');
  });

  it('findings list has no-findings placeholder initially', () => {
    const noFindings = document.getElementById('cloudenum-no-findings');
    expect(noFindings).not.toBeNull();
    expect(noFindings.style.display).not.toBe('none');
  });

  it('stats row is initially hidden', () => {
    const statsRow = document.getElementById('cloudenum-stats-row');
    expect(statsRow.style.display).toBe('none');
  });

  it('target mode select has all/single options', () => {
    const sel    = document.getElementById('cloudenum-target-mode');
    const values = Array.from(sel.options).map(o => o.value);
    expect(values).toContain('all');
    expect(values).toContain('single');
  });

  it('concurrency slider has min=1, max=50, default=10', () => {
    const slider = document.getElementById('cloudenum-concurrency');
    expect(slider.min).toBe('1');
    expect(slider.max).toBe('50');
    expect(slider.value).toBe('10');
  });

  it('open button has correct title attribute', () => {
    const btn = document.getElementById('btn-cloudenum-open');
    expect(btn.title).toMatch(/Container|Cloud|Docker|Kubernetes/i);
  });

  // ─── Behavioral tests ───────────────────────────────────────────────────────

  it('clicking start calls api.cloudEnum.start with state hosts and shows progress', async () => {
    const btnStart         = document.getElementById('btn-cloudenum-start');
    const btnStop          = document.getElementById('btn-cloudenum-stop');
    const progressContainer = document.getElementById('cloudenum-progress-container');

    btnStart.click();
    await flush();

    expect(api.cloudEnum.start).toHaveBeenCalledTimes(1);
    expect(api.cloudEnum.start).toHaveBeenCalledWith(
      expect.objectContaining({ targets: ['192.168.1.1'], concurrency: 10 })
    );
    expect(btnStart.disabled).toBe(true);
    expect(btnStop.disabled).toBe(false);
    expect(progressContainer.style.display).toBe('flex');
  });

  it('api.cloudEnum.start returning error status resets running state', async () => {
    api.cloudEnum.start.mockResolvedValue({ status: 'error', error: 'Already running' });

    const btnStart          = document.getElementById('btn-cloudenum-start');
    const btnStop           = document.getElementById('btn-cloudenum-stop');
    const progressContainer = document.getElementById('cloudenum-progress-container');
    const errorBanner       = document.getElementById('cloudenum-error-banner');

    btnStart.click();
    await flush();

    expect(btnStart.disabled).toBe(false);
    expect(btnStop.disabled).toBe(true);
    expect(progressContainer.style.display).toBe('none');
    expect(errorBanner.textContent).toMatch(/Already running/i);
  });

  it('clicking stop calls api.cloudEnum.stop and resets running state', async () => {
    const btnStart          = document.getElementById('btn-cloudenum-start');
    const btnStop           = document.getElementById('btn-cloudenum-stop');
    const progressContainer = document.getElementById('cloudenum-progress-container');

    // First start
    btnStart.click();
    await flush();
    expect(progressContainer.style.display).toBe('flex');

    // Then stop
    btnStop.click();
    await flush();

    expect(api.cloudEnum.stop).toHaveBeenCalledTimes(1);
    expect(btnStart.disabled).toBe(false);
    expect(btnStop.disabled).toBe(true);
    expect(progressContainer.style.display).toBe('none');
  });

  it('onFinding IPC callback appends a finding card to the list', () => {
    const findingsList = document.getElementById('cloudenum-findings-list');
    const noFindings   = document.getElementById('cloudenum-no-findings');
    const findingCb    = captureIpcCb(window.electronAPI.cloudEnum.onFinding);

    expect(findingCb).toBeTypeOf('function');

    findingCb({
      ip: '192.168.1.1', port: 2375, service: 'docker-daemon',
      severity: 'critical', title: 'Docker Exposed', evidence: 'HTTP 200',
      description: 'desc', remediation: 'fix', references: [], timestamp: Date.now(),
    });

    expect(state.cloudFindings).toHaveLength(1);
    expect(findingsList.querySelector('.cloudenum-finding-card')).not.toBeNull();
    expect(noFindings.style.display).toBe('none');
  });

  it('onProgress IPC callback updates progress bar and text', () => {
    const progressBar  = document.getElementById('cloudenum-progress-bar');
    const progressPct  = document.getElementById('cloudenum-progress-pct');
    const progressText = document.getElementById('cloudenum-progress-text');
    const progressCb   = captureIpcCb(window.electronAPI.cloudEnum.onProgress);

    expect(progressCb).toBeTypeOf('function');

    progressCb({ completed: 5, total: 10, percent: 50, currentIp: '192.168.1.5' });

    expect(progressBar.style.width).toBe('50%');
    expect(progressPct.textContent).toBe('50%');
    expect(progressText.textContent).toMatch(/5\/10/);
  });

  it('onComplete IPC callback resets running state', async () => {
    // Put the UI into running state first
    document.getElementById('btn-cloudenum-start').click();
    await flush();

    const completeCb        = captureIpcCb(window.electronAPI.cloudEnum.onComplete);
    const btnStart          = document.getElementById('btn-cloudenum-start');
    const btnStop           = document.getElementById('btn-cloudenum-stop');
    const progressContainer = document.getElementById('cloudenum-progress-container');

    expect(completeCb).toBeTypeOf('function');

    completeCb({ findings: 3, critical: 1, warning: 1, info: 1, elapsed: 2000, aborted: false });

    expect(btnStart.disabled).toBe(false);
    expect(btnStop.disabled).toBe(true);
    expect(progressContainer.style.display).toBe('none');
  });

  it('onError IPC callback shows error banner and resets running state', async () => {
    document.getElementById('btn-cloudenum-start').click();
    await flush();

    const errorCb    = captureIpcCb(window.electronAPI.cloudEnum.onError);
    const errorBanner = document.getElementById('cloudenum-error-banner');
    const btnStart    = document.getElementById('btn-cloudenum-start');
    const btnStop     = document.getElementById('btn-cloudenum-stop');

    expect(errorCb).toBeTypeOf('function');

    errorCb({ message: 'Scan failed unexpectedly' });

    expect(errorBanner.style.display).toBe('block');
    expect(errorBanner.textContent).toMatch(/Scan failed unexpectedly/i);
    expect(btnStart.disabled).toBe(false);
    expect(btnStop.disabled).toBe(true);
  });

  it('onFinding cards for non-matching IPs are hidden when single-IP filter is active', () => {
    // Simulate opening the panel pre-filtered to 192.168.1.1
    window.__openCloudEnumPanel('192.168.1.1');

    const findingCb = captureIpcCb(window.electronAPI.cloudEnum.onFinding);

    // Finding for a different host
    findingCb({
      ip: '10.0.0.99', port: 9090, service: 'prometheus',
      severity: 'info', title: 'Prometheus Exposed', evidence: 'HTTP 200',
      description: 'desc', remediation: 'fix', references: [], timestamp: Date.now(),
    });

    const card = document.querySelector('.cloudenum-finding-card[data-ip="10.0.0.99"]');
    expect(card).not.toBeNull();
    expect(card.style.display).toBe('none');
  });
});
