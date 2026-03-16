/**
 * Tests for Feature 7E — OAuth/OIDC Misconfiguration Scanner
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runOauthScan } from '../../../src/main/webapp/scanner/oauthScan.js';

const { mockSendProbe, mockMakeFinding } = vi.hoisted(() => ({
  mockSendProbe:   vi.fn(),
  mockMakeFinding: vi.fn((f) => ({ ...f, id: 'test-id' })),
}));

vi.mock('../../../src/main/webapp/scanner/index.js', () => ({
  sendProbe:    mockSendProbe,
  makeFinding:  mockMakeFinding,
  extractParams: vi.fn(() => []),
}));

const baseOpts = { signal: null, timeoutMs: 5000 };

beforeEach(() => {
  vi.resetAllMocks();
  mockMakeFinding.mockImplementation((f) => ({ ...f, id: 'test-id' }));
});

function makeTarget(url, overrides = {}) {
  return {
    url,
    method:         'GET',
    requestHeaders: {},
    responseHeaders:{},
    requestBody:    null,
    responseBody:   null,
    ...overrides,
  };
}

describe('runOauthScan', () => {
  it('skips non-OAuth endpoints', async () => {
    const findings = await runOauthScan(makeTarget('http://target.com/api/users'), baseOpts);
    expect(findings).toHaveLength(0);
    expect(mockSendProbe).not.toHaveBeenCalled();
  });

  it('detects open redirect in redirect_uri', async () => {
    mockSendProbe.mockResolvedValue({
      statusCode: 302,
      headers: { location: 'https://evil.com/callback?code=abc' },
      body: '',
    });

    const url = 'https://auth.example.com/oauth/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Flegit.com%2Fcb&state=xyz';
    const findings = await runOauthScan(makeTarget(url), baseOpts);
    const f = findings.find(f => f.title?.includes('Open Redirect'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('high');
    expect(f.parameter).toBe('redirect_uri');
  });

  it('detects missing state parameter', async () => {
    mockSendProbe.mockResolvedValue({ statusCode: 302, headers: { location: 'https://legit.com/cb' }, body: '' });

    const url = 'https://auth.example.com/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Flegit.com%2Fcb';
    const findings = await runOauthScan(makeTarget(url), baseOpts);
    const f = findings.find(f => f.title?.includes('state'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('medium');
  });

  it('detects authorization code leakage via Referer', async () => {
    const url = 'https://app.example.com/callback?code=abc123&state=xyz';
    const target = makeTarget(url, {
      requestHeaders: { referer: 'https://external-analytics.com/track' },
    });
    const findings = await runOauthScan(target, baseOpts);
    const f = findings.find(f => f.title?.includes('Leakage'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('medium');
  });

  it('detects token in URL query parameter', async () => {
    const url = 'https://app.example.com/callback?access_token=eyJhbGciOiJIUzI1NiJ9.test.sig&token_type=Bearer';
    const findings = await runOauthScan(makeTarget(url), baseOpts);
    const f = findings.find(f => f.title?.includes('Query Parameter'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('medium');
  });

  it('detects implicit flow via response_type=token', async () => {
    const url = 'https://auth.example.com/authorize?response_type=token&client_id=app&redirect_uri=https%3A%2F%2Flegit.com&state=xyz';
    const findings = await runOauthScan(makeTarget(url), baseOpts);
    const f = findings.find(f => f.title?.includes('Implicit Flow'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('medium');
  });

  it('detects missing PKCE on code flow', async () => {
    const url = 'https://auth.example.com/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Flegit.com&state=abc';
    const findings = await runOauthScan(makeTarget(url), baseOpts);
    const f = findings.find(f => f.title?.includes('PKCE'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('low');
  });

  it('does not flag PKCE when code_challenge is present', async () => {
    const url = 'https://auth.example.com/authorize?response_type=code&client_id=app&redirect_uri=https%3A%2F%2Flegit.com&state=abc&code_challenge=abc123&code_challenge_method=S256';
    const findings = await runOauthScan(makeTarget(url), baseOpts);
    expect(findings.find(f => f.title?.includes('PKCE'))).toBeUndefined();
  });

  it('detects client_secret in URL', async () => {
    const url = 'https://auth.example.com/token?grant_type=code&client_id=app&client_secret=supersecret&code=abc';
    const findings = await runOauthScan(makeTarget(url), baseOpts);
    const f = findings.find(f => f.title?.includes('Client Secret'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('high');
  });
});
