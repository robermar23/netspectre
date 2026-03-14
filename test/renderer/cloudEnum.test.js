/**
 * @vitest-environment jsdom
 * Feature 5C — Container & Cloud Enumeration — Renderer UI Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs   from 'fs';
import path from 'path';

const htmlDoc = fs.readFileSync(path.resolve(__dirname, '../../src/renderer/index.html'), 'utf8');

describe('Cloud Enum UI', () => {
  beforeEach(() => {
    document.body.innerHTML = htmlDoc;

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
  });

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
    const sel = document.getElementById('cloudenum-target-mode');
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
});
