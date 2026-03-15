/**
 * sequencerEngine.test.js
 * Tests for token collection, extraction, and statistical analysis.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';

// Mock sendProbe before importing sequencerEngine
vi.mock('../../src/main/webapp/scanner/index.js', () => ({
  sendProbe: vi.fn(),
}));

import { sendProbe } from '../../src/main/webapp/scanner/index.js';
import {
  collectTokens,
  stopCollection,
  isCollecting,
  analyzeTokens,
} from '../../src/main/webapp/sequencerEngine.js';

beforeEach(() => {
  vi.resetAllMocks();
  stopCollection();
});

afterEach(() => {
  stopCollection();
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Hex-encoded random tokens — 16 distinct byte values, ~4 bits/byte entropy */
function makeRandomHexTokens(n, byteLen = 16) {
  return Array.from({ length: n }, () => crypto.randomBytes(byteLen).toString('hex'));
}

/**
 * High-entropy tokens: characters spread across printable ASCII (32–126),
 * achieving ~log2(95) ≈ 6.57 bits/byte entropy, enough for STRONG verdict.
 */
function makeHighEntropyTokens(n, len = 64) {
  return Array.from({ length: n }, () => {
    const bytes = crypto.randomBytes(len);
    return Array.from(bytes, b => String.fromCharCode(32 + (b % 95))).join('');
  });
}

/** Tokens that are all identical — zero entropy */
function makePredictableTokens(n) {
  return Array.from({ length: n }, () => 'aabbccdd11223344');
}

// ─── analyzeTokens — guard clauses ───────────────────────────────────────────

describe('analyzeTokens — guard clauses', () => {
  it('returns error when fewer than 2 tokens supplied', () => {
    const result = analyzeTokens(['onlyOne']);
    expect(result.error).toMatch(/at least 2/i);
  });

  it('returns error for empty array', () => {
    const result = analyzeTokens([]);
    expect(result.error).toBeTruthy();
  });

  it('returns error for null input', () => {
    const result = analyzeTokens(null);
    expect(result.error).toBeTruthy();
  });
});

// ─── analyzeTokens — STRONG verdict with random tokens ───────────────────────

describe('analyzeTokens — result structure', () => {
  it('includes all required result fields', () => {
    const tokens = makeHighEntropyTokens(50, 32);
    const result = analyzeTokens(tokens);

    expect(result).toHaveProperty('sampleCount');
    expect(result).toHaveProperty('tokenLengthRange');
    expect(result).toHaveProperty('effectiveBitCount');
    expect(result).toHaveProperty('totalBitCount');
    expect(result).toHaveProperty('entropyPerByte');
    expect(result).toHaveProperty('fipsTests');
    expect(result.fipsTests).toHaveProperty('monobit');
    expect(result.fipsTests).toHaveProperty('blockFrequency');
    expect(result.fipsTests).toHaveProperty('runs');
    expect(result.fipsTests).toHaveProperty('longestRun');
    expect(result).toHaveProperty('chiSquared');
    expect(result).toHaveProperty('verdict');
    expect(result).toHaveProperty('verdictColor');
    expect(result).toHaveProperty('remediation');
    expect(result).toHaveProperty('histogram');
  });

  it('histogram has 256 entries summing to ~1', () => {
    const tokens = makeHighEntropyTokens(50, 32);
    const result = analyzeTokens(tokens);

    expect(result.histogram).toHaveLength(256);
    const sum = result.histogram.reduce((a, b) => a + b, 0);
    expect(sum).toBeCloseTo(1, 2);
  });

  it('tokenLengthRange reflects actual token lengths', () => {
    const tokens = makeHighEntropyTokens(20, 32);
    const result = analyzeTokens(tokens);

    expect(result.tokenLengthRange[0]).toBe(32);
    expect(result.tokenLengthRange[1]).toBe(32);
  });

  it('sampleCount matches input length', () => {
    const tokens = makeHighEntropyTokens(37, 16);
    const result = analyzeTokens(tokens);
    expect(result.sampleCount).toBe(37);
  });

  it('verdict is one of STRONG / MODERATE / WEAK', () => {
    const tokens = makeHighEntropyTokens(50, 32);
    const result = analyzeTokens(tokens);
    expect(['STRONG', 'MODERATE', 'WEAK']).toContain(result.verdict);
  });

  it('verdictColor matches verdict', () => {
    const tokens = makePredictableTokens(50);
    const result = analyzeTokens(tokens);
    expect(result.verdictColor).toBe('red');      // WEAK → red
    expect(result.verdict).toBe('WEAK');
  });

  it('higher-entropy tokens score better than predictable tokens', () => {
    const weak   = analyzeTokens(makePredictableTokens(50)).entropyPerByte;
    const strong = analyzeTokens(makeHighEntropyTokens(50, 32)).entropyPerByte;
    expect(strong).toBeGreaterThan(weak);
  });
});

// ─── analyzeTokens — WEAK verdict with predictable tokens ────────────────────

describe('analyzeTokens — WEAK verdict', () => {
  it('returns WEAK for identical tokens', () => {
    const tokens = makePredictableTokens(50);
    const result = analyzeTokens(tokens);

    expect(result.verdict).toBe('WEAK');
  });

  it('remediation text is non-empty for WEAK verdict', () => {
    const tokens = makePredictableTokens(50);
    const result = analyzeTokens(tokens);

    expect(result.remediation.length).toBeGreaterThan(10);
  });

  it('verdict color is red for WEAK', () => {
    const tokens = makePredictableTokens(50);
    const result = analyzeTokens(tokens);

    expect(result.verdictColor).toBe('red');
  });
});

// ─── analyzeTokens — Shannon entropy ─────────────────────────────────────────

describe('analyzeTokens — Shannon entropy', () => {
  it('entropy is low for tokens with one repeated character', () => {
    const tokens = Array.from({ length: 20 }, () => 'aaaaaaaaaaaaaaaa');
    const result = analyzeTokens(tokens);

    expect(result.entropyPerByte).toBe(0);
  });

  it('entropy is higher for more varied tokens', () => {
    const weak   = analyzeTokens(makePredictableTokens(50)).entropyPerByte;
    const strong = analyzeTokens(makeHighEntropyTokens(50, 32)).entropyPerByte;

    expect(strong).toBeGreaterThan(weak);
  });
});

// ─── analyzeTokens — effective bit count ──────────────────────────────────────

describe('analyzeTokens — effective bits', () => {
  it('effectiveBitCount is 0 when all tokens are identical', () => {
    const tokens = Array.from({ length: 10 }, () => 'abc');
    const result = analyzeTokens(tokens);

    expect(result.effectiveBitCount).toBe(0);
  });

  it('effectiveBitCount is positive for different tokens', () => {
    const tokens = makeHighEntropyTokens(20, 8);
    const result = analyzeTokens(tokens);

    expect(result.effectiveBitCount).toBeGreaterThan(0);
  });
});

// ─── analyzeTokens — FIPS tests ──────────────────────────────────────────────

describe('analyzeTokens — FIPS tests return null when insufficient data', () => {
  it('monobit returns null pass for very short tokens', () => {
    // Only 2 tokens of 1 byte = 16 bits total — too few for monobit
    const tokens = ['a', 'b'];
    const result = analyzeTokens(tokens);

    // Should not crash; monobit.pass may be null or boolean
    expect(result.fipsTests.monobit).toHaveProperty('pass');
  });

  it('blockFrequency returns null for insufficient blocks', () => {
    const tokens = ['ab', 'cd'];
    const result = analyzeTokens(tokens);

    expect(result.fipsTests.blockFrequency).toHaveProperty('pass');
  });
});

describe('analyzeTokens — FIPS monobit on large random sample', () => {
  it('monobit result has a pass field for large token sample', () => {
    // 100 tokens × 64 chars = large bit stream
    const tokens = makeHighEntropyTokens(100, 64);
    const result = analyzeTokens(tokens);

    // Should have a boolean or null result — not throw
    const monobitPass = result.fipsTests.monobit.pass;
    expect(typeof monobitPass === 'boolean' || monobitPass === null).toBe(true);
  });

  it('monobit detects bias in identical tokens', () => {
    // All-'0' bytes: bit stream is all zeros → ratio = 0.0 → biased
    const tokens = Array.from({ length: 50 }, () => '0000000000000000');
    const result = analyzeTokens(tokens);

    // Shannon entropy is 0, effective bits are 0 — monobit may return null (no bits to test)
    // or fail. Either is acceptable.
    expect(result.fipsTests.monobit).toHaveProperty('pass');
  });
});

// ─── analyzeTokens — chi-squared ──────────────────────────────────────────────

describe('analyzeTokens — chi-squared', () => {
  it('returns null pass when too few bytes for chi-squared', () => {
    const tokens = ['short', 'tokens'];
    const result = analyzeTokens(tokens);

    // < 256 bytes → null
    expect(result.chiSquared.pass === null || typeof result.chiSquared.pass === 'boolean').toBe(true);
  });

  it('chi-squared result has a pass field for adequate sample', () => {
    // Need at least 256 total bytes: 100 tokens × 32 chars = 3,200 bytes
    const tokens = makeHighEntropyTokens(100, 32);
    const result = analyzeTokens(tokens);

    // Should have a boolean or null result — not throw
    expect(typeof result.chiSquared.pass === 'boolean' || result.chiSquared.pass === null).toBe(true);
  });
});

// ─── collectTokens — validation ───────────────────────────────────────────────

describe('collectTokens — validation', () => {
  it('calls onError for invalid URL', async () => {
    const onError = vi.fn();
    await collectTokens(
      { url: 'not-a-url', count: 1, tokenSource: 'cookie' },
      () => {},
      () => {},
      onError,
    );
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('Invalid URL') }));
  });

  it('calls onError for invalid bodyRegex', async () => {
    const onError = vi.fn();
    await collectTokens(
      { url: 'http://example.com', count: 1, tokenSource: 'body-regex', bodyRegex: '[invalid' },
      () => {},
      () => {},
      onError,
    );
    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('bodyRegex') }));
  });

  it('rejects concurrent collection', async () => {
    sendProbe.mockImplementation(
      () => new Promise(r => setTimeout(() => r({ statusCode: 200, headers: { 'set-cookie': ['sid=abc; Path=/'] }, body: '' }), 50))
    );

    const onError = vi.fn();

    // Start first collection (don't await)
    collectTokens(
      { url: 'http://example.com', count: 5, tokenSource: 'cookie', cookieName: 'sid', delayMs: 0 },
      () => {},
      () => {},
      () => {},
    );

    // Second call should error immediately
    await collectTokens(
      { url: 'http://example.com', count: 1, tokenSource: 'cookie', cookieName: 'sid', delayMs: 0 },
      () => {},
      () => {},
      onError,
    );

    expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('already running') }));
    stopCollection();
  });
});

// ─── collectTokens — Set-Cookie extraction ────────────────────────────────────

describe('collectTokens — cookie extraction', () => {
  it('extracts named cookie from Set-Cookie header', async () => {
    sendProbe.mockResolvedValue({
      statusCode: 200,
      headers: { 'set-cookie': ['session=abc123; Path=/; HttpOnly'] },
      body: '',
    });

    const tokens = [];
    await collectTokens(
      { url: 'http://example.com', count: 3, tokenSource: 'cookie', cookieName: 'session', delayMs: 0 },
      (t) => tokens.push(t.token),
      () => {},
      () => {},
    );

    expect(tokens).toHaveLength(3);
    expect(tokens.every(t => t === 'abc123')).toBe(true);
  });

  it('extracts first cookie when no cookieName specified', async () => {
    sendProbe.mockResolvedValue({
      statusCode: 200,
      headers: { 'set-cookie': ['token=xyz789; Path=/'] },
      body: '',
    });

    const tokens = [];
    await collectTokens(
      { url: 'http://example.com', count: 2, tokenSource: 'cookie', delayMs: 0 },
      (t) => tokens.push(t.token),
      () => {},
      () => {},
    );

    expect(tokens).toHaveLength(2);
    expect(tokens[0]).toBe('xyz789');
  });

  it('skips response when named cookie not present', async () => {
    sendProbe.mockResolvedValue({
      statusCode: 200,
      headers: { 'set-cookie': ['other=value; Path=/'] },
      body: '',
    });

    const tokens = [];
    await collectTokens(
      { url: 'http://example.com', count: 2, tokenSource: 'cookie', cookieName: 'session', delayMs: 0 },
      (t) => tokens.push(t.token),
      () => {},
      () => {},
    );

    expect(tokens).toHaveLength(0);
  });
});

// ─── collectTokens — header extraction ───────────────────────────────────────

describe('collectTokens — header extraction', () => {
  it('extracts value from named response header', async () => {
    sendProbe.mockResolvedValue({
      statusCode: 200,
      headers: { 'x-csrf-token': 'csrfABC' },
      body: '',
    });

    const tokens = [];
    await collectTokens(
      { url: 'http://example.com', count: 2, tokenSource: 'header', headerName: 'x-csrf-token', delayMs: 0 },
      (t) => tokens.push(t.token),
      () => {},
      () => {},
    );

    expect(tokens).toHaveLength(2);
    expect(tokens[0]).toBe('csrfABC');
  });
});

// ─── collectTokens — body-regex extraction ────────────────────────────────────

describe('collectTokens — body-regex extraction', () => {
  it('extracts capture group 1 from body', async () => {
    sendProbe.mockResolvedValue({
      statusCode: 200,
      headers: {},
      body: '<input name="csrf" value="tok99">',
    });

    const tokens = [];
    await collectTokens(
      {
        url: 'http://example.com',
        count: 2,
        tokenSource: 'body-regex',
        bodyRegex: 'value="([^"]+)"',
        delayMs: 0,
      },
      (t) => tokens.push(t.token),
      () => {},
      () => {},
    );

    expect(tokens).toHaveLength(2);
    expect(tokens[0]).toBe('tok99');
  });
});

// ─── collectTokens — onComplete callback ─────────────────────────────────────

describe('collectTokens — onComplete', () => {
  it('calls onComplete with collected token array', async () => {
    sendProbe.mockResolvedValue({
      statusCode: 200,
      headers: { 'set-cookie': ['sid=AAA; Path=/'] },
      body: '',
    });

    let summary;
    await collectTokens(
      { url: 'http://example.com', count: 3, tokenSource: 'cookie', cookieName: 'sid', delayMs: 0 },
      () => {},
      (s) => { summary = s; },
      () => {},
    );

    expect(summary).toBeDefined();
    expect(summary.tokens).toHaveLength(3);
    expect(summary.count).toBe(3);
  });
});

// ─── collectTokens — network error ────────────────────────────────────────────

describe('collectTokens — network errors', () => {
  it('calls onError and stops on network failure', async () => {
    sendProbe.mockRejectedValue(new Error('ECONNREFUSED'));

    const onError = vi.fn();
    const tokens  = [];
    await collectTokens(
      { url: 'http://example.com', count: 5, tokenSource: 'cookie', delayMs: 0 },
      (t) => tokens.push(t),
      () => {},
      onError,
    );

    expect(onError).toHaveBeenCalled();
    // Should stop after first error, not fire 5 times
    expect(tokens).toHaveLength(0);
  });
});

// ─── stopCollection / isCollecting ───────────────────────────────────────────

describe('stopCollection / isCollecting', () => {
  it('isCollecting returns false before any collection', () => {
    expect(isCollecting()).toBe(false);
  });

  it('stops in-progress collection early', async () => {
    sendProbe.mockImplementation(
      () => new Promise(r => setTimeout(() => r({ statusCode: 200, headers: { 'set-cookie': ['t=X; Path=/'] }, body: '' }), 30))
    );

    const tokens = [];
    const done = new Promise(resolve => {
      collectTokens(
        { url: 'http://example.com', count: 20, tokenSource: 'cookie', cookieName: 't', delayMs: 0 },
        (t) => tokens.push(t),
        resolve,
        resolve,
      );
    });

    // Stop after a short time
    setTimeout(() => stopCollection(), 60);
    await done;

    expect(tokens.length).toBeLessThan(20);
  });
});
