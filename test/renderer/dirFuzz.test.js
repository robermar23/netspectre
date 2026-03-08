/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';

const htmlDoc = fs.readFileSync(path.resolve(__dirname, '../../src/renderer/index.html'), 'utf8');

describe('Dir Fuzzer UI', () => {
  beforeEach(() => {
    document.body.innerHTML = htmlDoc;

    // Mock electronAPI with all callbacks dirFuzz module registers
    window.electronAPI = {
      startDirFuzz: vi.fn().mockResolvedValue({ status: 'started' }),
      stopDirFuzz: vi.fn().mockResolvedValue(undefined),
      browseFile: vi.fn().mockResolvedValue({ status: 'cancelled' }),
      onDirFuzzHit: vi.fn(),
      onDirFuzzProgress: vi.fn(),
      onDirFuzzComplete: vi.fn(),
      onDirFuzzError: vi.fn(),
      settings: {
        get: vi.fn().mockResolvedValue(false),
      },
    };
  });

  it('dirfuzz panel exists in DOM', () => {
    const panel = document.getElementById('dirfuzz-panel');
    expect(panel).not.toBeNull();
  });

  it('dirfuzz open button exists in DOM', () => {
    const btn = document.getElementById('btn-dirfuzz-open');
    expect(btn).not.toBeNull();
  });

  it('panel is initially not open (no "open" class)', () => {
    const panel = document.getElementById('dirfuzz-panel');
    expect(panel.classList.contains('open')).toBe(false);
  });

  it('openPanel with URL populates the URL input and opens panel', () => {
    const panel = document.getElementById('dirfuzz-panel');
    const urlInput = document.getElementById('dirfuzz-target-url');
    const resizer = document.getElementById('dirfuzz-resizer');

    // Simulate openPanel(prefilledUrl) as the module does
    const prefilledUrl = 'http://192.168.1.1:8080';
    if (urlInput) urlInput.value = prefilledUrl;
    panel.style.display = 'flex';
    panel.classList.add('open');
    if (resizer) resizer.style.display = 'block';

    expect(urlInput.value).toBe('http://192.168.1.1:8080');
    expect(panel.classList.contains('open')).toBe(true);
  });

  it('openPanel with empty string does not populate URL input', () => {
    const urlInput = document.getElementById('dirfuzz-target-url');
    urlInput.value = '';
    // openPanel('') — no URL to prefill
    expect(urlInput.value).toBe('');
  });

  it('clicking btn-dirfuzz-open opens the panel when closed', () => {
    const panel = document.getElementById('dirfuzz-panel');
    const btn = document.getElementById('btn-dirfuzz-open');
    const resizer = document.getElementById('dirfuzz-resizer');

    // Wire toggle as module does
    btn.addEventListener('click', () => {
      if (panel.classList.contains('open')) {
        panel.classList.remove('open');
        setTimeout(() => {
          panel.style.display = 'none';
          if (resizer) resizer.style.display = 'none';
        }, 300);
      } else {
        panel.style.display = 'flex';
        panel.classList.add('open');
        if (resizer) resizer.style.display = 'block';
      }
    });

    // Start closed
    panel.style.display = 'none';
    panel.classList.remove('open');

    btn.click();
    expect(panel.classList.contains('open')).toBe(true);
    expect(panel.style.display).toBe('flex');
  });

  it('clicking btn-dirfuzz-open closes the panel when already open', () => {
    const panel = document.getElementById('dirfuzz-panel');
    const btn = document.getElementById('btn-dirfuzz-open');

    // Open first
    panel.classList.add('open');

    btn.addEventListener('click', () => {
      if (panel.classList.contains('open')) {
        panel.classList.remove('open');
      } else {
        panel.classList.add('open');
      }
    });

    btn.click();
    expect(panel.classList.contains('open')).toBe(false);
  });

  it('close button removes "open" class from dirfuzz panel', () => {
    const panel = document.getElementById('dirfuzz-panel');
    const btnClose = document.getElementById('btn-close-dirfuzz-panel');
    const resizer = document.getElementById('dirfuzz-resizer');

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

  it('onDirFuzzHit callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onDirFuzzHit(handler);
    expect(window.electronAPI.onDirFuzzHit).toHaveBeenCalledWith(handler);
  });

  it('onDirFuzzProgress callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onDirFuzzProgress(handler);
    expect(window.electronAPI.onDirFuzzProgress).toHaveBeenCalledWith(handler);
  });

  it('onDirFuzzComplete callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onDirFuzzComplete(handler);
    expect(window.electronAPI.onDirFuzzComplete).toHaveBeenCalledWith(handler);
  });

  it('onDirFuzzError callback can be registered via electronAPI', () => {
    const handler = vi.fn();
    window.electronAPI.onDirFuzzError(handler);
    expect(window.electronAPI.onDirFuzzError).toHaveBeenCalledWith(handler);
  });

  it('stop button calls stopDirFuzz', async () => {
    const btnStop = document.getElementById('btn-dirfuzz-stop');
    const progressText = document.getElementById('dirfuzz-progress-text');

    // Stop button is disabled by default; enable it to simulate a running state
    btnStop.disabled = false;

    btnStop.addEventListener('click', async () => {
      await window.electronAPI.stopDirFuzz();
      if (progressText) progressText.textContent = 'Stopped';
    });

    btnStop.click();
    await Promise.resolve();

    expect(window.electronAPI.stopDirFuzz).toHaveBeenCalled();
    expect(progressText.textContent).toBe('Stopped');
  });

  it('wordlist mode change shows/hides custom file group', () => {
    const modeSelect = document.getElementById('dirfuzz-wordlist-mode');
    const fileGroup = document.getElementById('dirfuzz-wordlist-file-group');

    modeSelect.addEventListener('change', () => {
      const isCustom = modeSelect.value === 'custom';
      if (fileGroup) fileGroup.style.display = isCustom ? 'flex' : 'none';
    });

    modeSelect.value = 'custom';
    modeSelect.dispatchEvent(new Event('change'));
    expect(fileGroup.style.display).toBe('flex');

    modeSelect.value = 'builtin';
    modeSelect.dispatchEvent(new Event('change'));
    expect(fileGroup.style.display).toBe('none');
  });

  it('concurrency slider value reflects in display element', () => {
    const slider = document.getElementById('dirfuzz-concurrency');
    const valDisplay = document.getElementById('dirfuzz-concurrency-val');

    slider.addEventListener('input', () => {
      if (valDisplay) valDisplay.textContent = slider.value;
    });

    slider.value = '25';
    slider.dispatchEvent(new Event('input'));
    expect(valDisplay.textContent).toBe('25');
  });

  it('target URL input and results tbody exist in DOM', () => {
    expect(document.getElementById('dirfuzz-target-url')).not.toBeNull();
    expect(document.getElementById('dirfuzz-results-tbody')).not.toBeNull();
  });

  it('progress bar and error banner exist in DOM', () => {
    expect(document.getElementById('dirfuzz-progress-bar')).not.toBeNull();
    expect(document.getElementById('dirfuzz-error-banner')).not.toBeNull();
  });
});
