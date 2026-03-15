/**
 * intruderEngine.test.js
 * Tests for the Intruder payload expansion, position parsing, and request firing.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock sendProbe before importing intruderEngine
vi.mock('../../src/main/webapp/scanner/index.js', () => ({
  sendProbe: vi.fn(),
}));

import { sendProbe } from '../../src/main/webapp/scanner/index.js';
import {
  parsePositions,
  applyPayloads,
  applyTransforms,
  generateRequests,
  startIntruder,
  stopIntruder,
  isIntruderRunning,
  cleanupIntruder,
} from '../../src/main/webapp/intruderEngine.js';

beforeEach(() => {
  vi.resetAllMocks();
  cleanupIntruder();
});

afterEach(() => {
  cleanupIntruder();
});

// ─── parsePositions ───────────────────────────────────────────────────────────

describe('parsePositions', () => {
  it('finds one position', () => {
    const pos = parsePositions('GET /login?user=§admin§ HTTP/1.1');
    expect(pos).toHaveLength(1);
    expect(pos[0].value).toBe('admin');
  });

  it('finds two positions', () => {
    const pos = parsePositions('user=§admin§&pass=§password§');
    expect(pos).toHaveLength(2);
    expect(pos[0].value).toBe('admin');
    expect(pos[1].value).toBe('password');
  });

  it('returns empty array when no markers', () => {
    expect(parsePositions('GET / HTTP/1.1')).toHaveLength(0);
  });

  it('handles empty string', () => {
    expect(parsePositions('')).toHaveLength(0);
  });
});

// ─── applyPayloads ────────────────────────────────────────────────────────────

describe('applyPayloads', () => {
  it('replaces single position', () => {
    const tmpl = 'user=§admin§';
    const pos  = parsePositions(tmpl);
    expect(applyPayloads(tmpl, pos, ["' OR 1=1--"])).toBe("user=' OR 1=1--");
  });

  it('replaces two positions independently', () => {
    const tmpl = 'user=§admin§&pass=§password§';
    const pos  = parsePositions(tmpl);
    expect(applyPayloads(tmpl, pos, ['root', 'secret'])).toBe('user=root&pass=secret');
  });

  it('preserves text outside markers', () => {
    const tmpl = 'prefix-§VALUE§-suffix';
    const pos  = parsePositions(tmpl);
    expect(applyPayloads(tmpl, pos, ['X'])).toBe('prefix-X-suffix');
  });
});

// ─── applyTransforms ─────────────────────────────────────────────────────────

describe('applyTransforms', () => {
  it('url-encode encodes special chars', () => {
    expect(applyTransforms("' OR 1=1", ['url-encode'])).toBe("'%20OR%201%3D1");
  });

  it('base64-encode produces base64', () => {
    expect(applyTransforms('admin', ['base64-encode'])).toBe(Buffer.from('admin').toString('base64'));
  });

  it('uppercase transforms', () => {
    expect(applyTransforms('admin', ['uppercase'])).toBe('ADMIN');
  });

  it('reverse transforms', () => {
    expect(applyTransforms('abc', ['reverse'])).toBe('cba');
  });

  it('chains multiple transforms', () => {
    const result = applyTransforms('a b', ['uppercase', 'url-encode']);
    expect(result).toBe('A%20B');
  });

  it('handles empty transforms array', () => {
    expect(applyTransforms('test', [])).toBe('test');
  });
});

// ─── generateRequests — Sniper ────────────────────────────────────────────────

describe('generateRequests — sniper', () => {
  it('generates position × payload count requests', () => {
    const tmpl = 'user=§a§&pass=§b§';
    const pos  = parsePositions(tmpl);
    const reqs = [...generateRequests('sniper', pos, [['x', 'y', 'z']])];
    // 2 positions × 3 payloads = 6 requests
    expect(reqs).toHaveLength(6);
  });

  it('leaves other positions unchanged in sniper mode', () => {
    const tmpl = 'user=§admin§&pass=§pass§';
    const pos  = parsePositions(tmpl);
    const reqs = [...generateRequests('sniper', pos, [['hack']])];
    // req[0]: position 0 injected, position 1 untouched
    expect(reqs[0].payloads[0]).toBe('hack');
    expect(reqs[0].payloads[1]).toBe('pass');
    // req[1]: position 1 injected, position 0 untouched
    expect(reqs[1].payloads[0]).toBe('admin');
    expect(reqs[1].payloads[1]).toBe('hack');
  });
});

// ─── generateRequests — BatteringRam ─────────────────────────────────────────

describe('generateRequests — battering-ram', () => {
  it('applies same payload to all positions', () => {
    const tmpl = 'user=§a§&pass=§b§';
    const pos  = parsePositions(tmpl);
    const reqs = [...generateRequests('battering-ram', pos, [['x', 'y']])];
    expect(reqs).toHaveLength(2);
    expect(reqs[0].payloads).toEqual(['x', 'x']);
    expect(reqs[1].payloads).toEqual(['y', 'y']);
  });
});

// ─── generateRequests — Pitchfork ────────────────────────────────────────────

describe('generateRequests — pitchfork', () => {
  it('iterates lists in parallel, capped to shortest', () => {
    const tmpl = 'user=§a§&pass=§b§';
    const pos  = parsePositions(tmpl);
    const reqs = [...generateRequests('pitchfork', pos, [['u1','u2','u3'], ['p1','p2']])];
    expect(reqs).toHaveLength(2); // shortest list has 2 items
    expect(reqs[0].payloads).toEqual(['u1','p1']);
    expect(reqs[1].payloads).toEqual(['u2','p2']);
  });
});

// ─── generateRequests — ClusterBomb ──────────────────────────────────────────

describe('generateRequests — cluster-bomb', () => {
  it('generates cartesian product', () => {
    const tmpl = 'user=§a§&pass=§b§';
    const pos  = parsePositions(tmpl);
    const reqs = [...generateRequests('cluster-bomb', pos, [['u1','u2'], ['p1','p2','p3']])];
    expect(reqs).toHaveLength(6); // 2 × 3
  });

  it('caps at 1,000,000 requests', () => {
    const tmpl = 'x=§a§&y=§b§';
    const pos  = parsePositions(tmpl);
    // Each list has 1001 items → 1,001 × 1,001 = 1,002,001 > 1,000,000
    const bigList = Array.from({ length: 1001 }, (_, i) => String(i));
    const reqs = [...generateRequests('cluster-bomb', pos, [bigList, bigList])];
    expect(reqs.length).toBeLessThanOrEqual(1_000_000);
  });
});

// ─── startIntruder ────────────────────────────────────────────────────────────

describe('startIntruder', () => {
  const baseOpts = {
    rawTemplate:  'GET /§path§ HTTP/1.1\nHost: target.com\n\n',
    targetUrl:    'http://target.com',
    attackType:   'sniper',
    payloadLists: [['a', 'b']],
    concurrency:  2,
    delayMs:      0,
    timeoutMs:    5000,
  };

  it('fires one request per payload and emits results', async () => {
    sendProbe.mockResolvedValue({ statusCode: 200, body: 'OK', durationMs: 10 });

    const results = [];
    await new Promise((resolve) => {
      startIntruder(
        baseOpts,
        (r) => results.push(r),
        () => {},
        resolve,
        (err) => { throw err; },
      );
    });

    expect(results).toHaveLength(2);
    expect(results.every(r => r.statusCode === 200)).toBe(true);
  });

  it('calls onComplete with total count', async () => {
    sendProbe.mockResolvedValue({ statusCode: 200, body: '', durationMs: 5 });

    let summary;
    await new Promise((resolve) => {
      startIntruder(
        baseOpts,
        () => {},
        () => {},
        (s) => { summary = s; resolve(); },
        (err) => { throw err; },
      );
    });

    expect(summary.total).toBe(2);
    expect(summary.completed).toBe(2);
  });

  it('handles network errors gracefully — emits error field on result', async () => {
    sendProbe.mockRejectedValue(new Error('ECONNREFUSED'));

    const results = [];
    await new Promise((resolve) => {
      startIntruder(
        baseOpts,
        (r) => results.push(r),
        () => {},
        resolve,
        () => {},
      );
    });

    expect(results.some(r => r.error)).toBe(true);
  });

  it('returns error when rawTemplate is missing', () => {
    const onError = vi.fn();
    startIntruder({ ...baseOpts, rawTemplate: '' }, () => {}, () => {}, () => {}, onError);
    expect(onError).toHaveBeenCalled();
  });

  it('returns error when no §markers§ found', () => {
    const onError = vi.fn();
    startIntruder({ ...baseOpts, rawTemplate: 'GET / HTTP/1.1\n\n' }, () => {}, () => {}, () => {}, onError);
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('marker') }));
  });

  it('stops mid-run on abort', async () => {
    // Each request takes 50ms; we stop after starting
    sendProbe.mockImplementation(() => new Promise(r => setTimeout(() => r({ statusCode: 200, body: '', durationMs: 50 }), 50)));

    const opts = {
      ...baseOpts,
      payloadLists: [Array.from({ length: 20 }, (_, i) => String(i))],
      concurrency: 1,
    };

    const results = [];
    const runPromise = new Promise((resolve) => {
      startIntruder(opts, (r) => results.push(r), () => {}, resolve, () => resolve());
    });

    // Abort after a short delay
    setTimeout(() => stopIntruder(), 80);
    await runPromise;

    // Should have completed fewer than all 20 requests
    expect(results.length).toBeLessThan(20);
  });

  it('rejects concurrent starts', () => {
    sendProbe.mockResolvedValue({ statusCode: 200, body: '', durationMs: 1 });

    // Don't await — let it run in the background
    startIntruder(baseOpts, () => {}, () => {}, () => {}, () => {});

    const onError = vi.fn();
    startIntruder(baseOpts, () => {}, () => {}, () => {}, onError);
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('already') }));

    cleanupIntruder();
  });
});
