/**
 * Tests for Feature 7E — Open Redirect Detection Module
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runOpenRedirect } from '../../../src/main/webapp/scanner/openRedirect.js';

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
    method:          'GET',
    requestHeaders:  {},
    responseHeaders: {},
    requestBody:     null,
    responseBody:    null,
    ...overrides,
  };
}

describe('runOpenRedirect', () => {
  it('returns no findings for URL without redirect params', async () => {
    const findings = await runOpenRedirect(makeTarget('http://target.com/api/users?id=1'), baseOpts);
    expect(findings).toHaveLength(0);
  });

  it('detects direct open redirect via Location header', async () => {
    mockSendProbe.mockResolvedValue({
      statusCode: 302,
      headers: { location: 'https://evil-redir.netspectre.test/phish' },
      body: '',
    });

    const findings = await runOpenRedirect(
      makeTarget('http://target.com/login?redirect=https%3A%2F%2Flegit.com'),
      baseOpts,
    );
    const f = findings.find(f => f.title?.includes('Open Redirect'));
    expect(f).toBeDefined();
    expect(f.parameter).toBe('redirect');
    expect(f.severity).toBe('medium');
  });

  it('detects body-based JS redirect', async () => {
    mockSendProbe.mockResolvedValue({
      statusCode: 200,
      headers: {},
      body: '<script>window.location = "https://evil-redir.netspectre.test/phish";</script>',
    });

    const findings = await runOpenRedirect(
      makeTarget('http://target.com/logout?returnUrl=https%3A%2F%2Flegit.com'),
      baseOpts,
    );
    const f = findings.find(f => f.title?.includes('Open Redirect'));
    expect(f).toBeDefined();
    expect(f.evidence.redirectType).toContain('body redirect');
  });

  it('detects redirect on "next" parameter', async () => {
    mockSendProbe.mockResolvedValue({
      statusCode: 301,
      headers: { location: 'https://evil-redir.netspectre.test/' },
      body: '',
    });

    const findings = await runOpenRedirect(
      makeTarget('http://target.com/auth?next=https%3A%2F%2Flegit.com%2Fdashboard'),
      baseOpts,
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].parameter).toBe('next');
  });

  it('detects redirect on URL-valued parameter (heuristic)', async () => {
    mockSendProbe.mockResolvedValue({
      statusCode: 302,
      headers: { location: 'https://evil-redir.netspectre.test/' },
      body: '',
    });

    const findings = await runOpenRedirect(
      makeTarget('http://target.com/redir?go=https%3A%2F%2Flegit.com'),
      baseOpts,
    );
    expect(findings.find(f => f.parameter === 'go')).toBeDefined();
  });

  it('does not flag same-domain redirect', async () => {
    mockSendProbe.mockResolvedValue({
      statusCode: 302,
      headers: { location: 'https://target.com/dashboard' },
      body: '',
    });

    const findings = await runOpenRedirect(
      makeTarget('http://target.com/login?redirect=https%3A%2F%2Flegit.com'),
      baseOpts,
    );
    // Should probe but not flag since location is same domain
    expect(findings.find(f => f.title?.includes('Open Redirect'))).toBeUndefined();
  });

  it('does not flag when server returns 200 with no redirect indicators', async () => {
    mockSendProbe.mockResolvedValue({
      statusCode: 200,
      headers: {},
      body: '<html><body>Welcome</body></html>',
    });

    const findings = await runOpenRedirect(
      makeTarget('http://target.com/login?redirect=https%3A%2F%2Flegit.com'),
      baseOpts,
    );
    expect(findings).toHaveLength(0);
  });

  it('handles AbortError gracefully', async () => {
    mockSendProbe.mockRejectedValue(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
    const findings = await runOpenRedirect(
      makeTarget('http://target.com/login?redirect=https%3A%2F%2Flegit.com'),
      baseOpts,
    );
    expect(findings).toHaveLength(0);
  });

  it('stops probing after first hit on a param', async () => {
    mockSendProbe.mockResolvedValue({
      statusCode: 302,
      headers: { location: 'https://evil-redir.netspectre.test/' },
      body: '',
    });

    const findings = await runOpenRedirect(
      makeTarget('http://target.com/login?redirect=https%3A%2F%2Flegit.com'),
      baseOpts,
    );
    // Should only have one finding for the "redirect" parameter even though 8 payloads are tried
    const redirectFindings = findings.filter(f => f.parameter === 'redirect');
    expect(redirectFindings).toHaveLength(1);
  });
});
