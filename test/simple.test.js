import { describe, it, expect, vi } from 'vitest';

// Mock dependencies of hardeningMonitor.js
vi.mock('electron-store', () => {
  return {
    default: class MockStore {
      constructor() {
        this.get = vi.fn();
        this.set = vi.fn();
      }
    }
  };
});
vi.mock('electron', () => ({
  Notification: vi.fn(),
  ipcMain: { handle: vi.fn(), on: vi.fn() }
}));
vi.mock('ping', () => ({ default: { promise: { probe: vi.fn() } } }));
vi.mock('../src/main/scanner.js', () => ({ enrichHost: vi.fn(), getArpTable: vi.fn() }));

import * as monitor from '../src/main/hardeningMonitor.js';

describe('Simple Load', () => {
  it('should load the module', () => {
    expect(monitor).toBeDefined();
    console.log('monitor keys:', Object.keys(monitor));
    expect(typeof monitor.validateCidr).toBe('function');
  });
});
