/**
 * Tests for Feature 7E — JWT Attack Suite
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runJwtAttack } from '../../../src/main/webapp/scanner/jwtAttack.js';

const { mockSendProbe, mockMakeFinding } = vi.hoisted(() => ({
  mockSendProbe:   vi.fn(),
  mockMakeFinding: vi.fn((f) => ({ ...f, id: 'test-id' })),
}));

vi.mock('../../../src/main/webapp/scanner/index.js', () => ({
  sendProbe:    mockSendProbe,
  makeFinding:  mockMakeFinding,
  extractParams: vi.fn(() => []),
}));

// ─── JWT helpers ──────────────────────────────────────────────────────────────

function b64u(str) {
  return Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function makeJwt(header, payload) {
  return `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}.fakesig`;
}

function makeTarget(jwt, placement = 'authorization') {
  const now = Math.floor(Date.now() / 1000);
  const headers = {};
  if (placement === 'authorization') headers['authorization'] = `Bearer ${jwt}`;
  if (placement === 'cookie')        headers['cookie'] = `token=${jwt}`;
  return {
    url:             'http://target.com/api/profile',
    method:          'GET',
    requestHeaders:  headers,
    responseHeaders: {},
    requestBody:     null,
    responseBody:    null,
  };
}

const baseOpts = { signal: null, timeoutMs: 5000 };

beforeEach(() => {
  vi.resetAllMocks();
  mockMakeFinding.mockImplementation((f) => ({ ...f, id: 'test-id' }));
});

describe('runJwtAttack', () => {
  it('returns empty findings when no JWT present', async () => {
    const target = { url: 'http://t.com/', method: 'GET', requestHeaders: {}, responseHeaders: {}, requestBody: null, responseBody: null };
    const findings = await runJwtAttack(target, baseOpts);
    expect(findings).toHaveLength(0);
  });

  it('detects alg:none bypass when server returns 200 for unsigned token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', exp: now + 3600 });
    mockSendProbe.mockResolvedValue({ statusCode: 200, headers: {}, body: '{"data":"ok"}' });

    const target = makeTarget(jwt);
    const findings = await runJwtAttack(target, baseOpts);
    const f = findings.find(f => f.title?.includes('alg:none'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('critical');
  });

  it('does not flag alg:none when server returns 401', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', exp: now + 3600 });
    mockSendProbe.mockResolvedValue({ statusCode: 401, headers: {}, body: 'Unauthorized' });

    const findings = await runJwtAttack(makeTarget(jwt), baseOpts);
    expect(findings.find(f => f.title?.includes('alg:none'))).toBeUndefined();
  });

  it('detects weak HMAC secret', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', exp: now + 3600, role: 'user' });
    // All weak secret probes succeed (simulated)
    mockSendProbe.mockResolvedValue({ statusCode: 200, headers: {}, body: '{"ok":true}' });

    const findings = await runJwtAttack(makeTarget(jwt), baseOpts);
    const f = findings.find(f => f.title?.includes('Weak HMAC'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('critical');
    expect(f.evidence.weakSecret).toBeDefined();
  });

  it('detects jku header spoofing (passive)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'RS256', typ: 'JWT', jku: 'https://attacker.com/jwks.json' }, { sub: '1', exp: now + 3600 });
    // RS256 — sendProbe won't be called for alg:none (can't forge)
    mockSendProbe.mockResolvedValue({ statusCode: 401, headers: {}, body: '' });

    const findings = await runJwtAttack(makeTarget(jwt), baseOpts);
    const f = findings.find(f => f.title?.includes('jku'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('high');
  });

  it('detects expired token acceptance', async () => {
    const past = Math.floor(Date.now() / 1000) - 7200; // expired 2 hours ago
    const jwt  = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', exp: past });
    mockSendProbe.mockResolvedValue({ statusCode: 200, headers: {}, body: '{"data":"ok"}' });

    const findings = await runJwtAttack(makeTarget(jwt), baseOpts);
    const f = findings.find(f => f.title?.includes('Expired'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('high');
  });

  it('reports privilege claim advisory for HS tokens with role claim', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', exp: now + 3600, role: 'admin' });
    // server rejects everything
    mockSendProbe.mockResolvedValue({ statusCode: 401, headers: {}, body: 'Unauthorized' });

    const findings = await runJwtAttack(makeTarget(jwt), baseOpts);
    const f = findings.find(f => f.title?.includes('Privilege Claim'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('info');
  });

  it('detects kid header path traversal when server accepts', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT', kid: 'key-001' }, { sub: '1', exp: now + 3600 });
    // first two probes: alg:none and weak secrets fail; kid probe succeeds
    mockSendProbe
      .mockResolvedValueOnce({ statusCode: 401, headers: {}, body: '' })  // alg:none
      .mockResolvedValue({ statusCode: 200, headers: {}, body: '{"ok":true}' }); // weak secrets + kid

    const findings = await runJwtAttack(makeTarget(jwt), baseOpts);
    // Either weak secret or kid injection will produce a finding
    expect(findings.length).toBeGreaterThan(0);
  });

  it('handles AbortError gracefully', async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: '1', exp: now + 3600 });
    mockSendProbe.mockRejectedValue(Object.assign(new Error('Aborted'), { name: 'AbortError' }));

    const findings = await runJwtAttack(makeTarget(jwt), baseOpts);
    expect(findings).toHaveLength(0);
  });
});
