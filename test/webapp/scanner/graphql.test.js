/**
 * Tests for Feature 7E — GraphQL Scanner Module
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runGraphql } from '../../../src/main/webapp/scanner/graphql.js';

// ─── Mock scanner/index.js dependencies ──────────────────────────────────────

const { mockSendProbe, mockMakeFinding } = vi.hoisted(() => ({
  mockSendProbe:  vi.fn(),
  mockMakeFinding: vi.fn((fields) => ({ ...fields, id: 'test-id', timestamp: 0 })),
}));

vi.mock('../../../src/main/webapp/scanner/index.js', () => ({
  sendProbe:   mockSendProbe,
  makeFinding: mockMakeFinding,
  extractParams: vi.fn(() => []),
}));

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeTarget(overrides = {}) {
  return {
    url:             'http://target.com/graphql',
    method:          'POST',
    requestHeaders:  { 'content-type': 'application/json' },
    responseHeaders: { 'content-type': 'application/json' },
    responseBody:    JSON.stringify({ data: { __schema: { types: [] } } }),
    requestBody:     null,
    ...overrides,
  };
}

const baseOpts = { signal: null, timeoutMs: 5000, oastCallbackUrl: null };

beforeEach(() => {
  vi.resetAllMocks();
  mockMakeFinding.mockImplementation((f) => ({ ...f, id: 'test-id' }));
});

describe('runGraphql', () => {
  it('skips non-GraphQL endpoints', async () => {
    const target = makeTarget({ url: 'http://target.com/api/users' });
    // Non-JSON response, no graphql path
    target.responseHeaders = { 'content-type': 'text/html' };
    const findings = await runGraphql(target, baseOpts);
    expect(mockSendProbe).not.toHaveBeenCalled();
    expect(findings).toHaveLength(0);
  });

  it('detects introspection enabled', async () => {
    mockSendProbe.mockResolvedValue({
      statusCode: 200,
      body: JSON.stringify({ data: { __schema: { types: [{ name: 'Query', kind: 'OBJECT' }, { name: 'User', kind: 'OBJECT' }, { name: 'String', kind: 'SCALAR' }] } } }),
      headers: {},
    });
    const findings = await runGraphql(makeTarget(), baseOpts);
    const f = findings.find(f => f.title?.includes('Introspection'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('medium');
    expect(f.evidence.typeCount).toBe(3);
  });

  it('detects batch query acceptance', async () => {
    // First call: introspection (empty schema)
    mockSendProbe
      .mockResolvedValueOnce({ statusCode: 200, body: JSON.stringify({ data: { __schema: { types: [] } } }), headers: {} })
      // Second call: batch (100 results)
      .mockResolvedValueOnce({ statusCode: 200, body: JSON.stringify(Array.from({ length: 100 }, () => ({ data: { __typename: 'Query' } }))), headers: {} })
      // Remaining calls
      .mockResolvedValue({ statusCode: 400, body: '', headers: {} });

    const findings = await runGraphql(makeTarget(), baseOpts);
    const f = findings.find(f => f.title?.includes('Batch'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('medium');
  });

  it('detects field suggestion leakage', async () => {
    mockSendProbe
      .mockResolvedValueOnce({ statusCode: 200, body: '{}', headers: {} })           // introspection — no data
      .mockResolvedValueOnce({ statusCode: 200, body: '[]', headers: {} })           // batch — not array length
      .mockResolvedValueOnce({ statusCode: 400, body: 'errors', headers: {} })       // nested DoS (fast reject)
      .mockResolvedValueOnce({                                                         // field suggestion
        statusCode: 200,
        body: JSON.stringify({ errors: [{ message: 'Cannot query field "nsProbeField_typo". Did you mean "id"?' }] }),
        headers: {},
      })
      .mockResolvedValue({ statusCode: 400, body: '', headers: {} });

    const findings = await runGraphql(makeTarget(), baseOpts);
    const f = findings.find(f => f.title?.includes('Suggestion'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('low');
  });

  it('detects SQL injection via resolver arguments', async () => {
    mockSendProbe
      .mockResolvedValueOnce({ statusCode: 200, body: '{}', headers: {} })
      .mockResolvedValueOnce({ statusCode: 200, body: '[]', headers: {} })
      .mockResolvedValueOnce({ statusCode: 400, body: '', headers: {} })
      .mockResolvedValueOnce({ statusCode: 200, body: '', headers: {} })  // field suggestion — no match
      .mockResolvedValueOnce({
        statusCode: 500,
        body: "You have an error in your SQL syntax near '1' OR '1'='1'",
        headers: {},
      });

    const findings = await runGraphql(makeTarget(), baseOpts);
    const f = findings.find(f => f.title?.includes('SQL Injection'));
    expect(f).toBeDefined();
    expect(f.severity).toBe('critical');
  });

  it('aborts cleanly on AbortError', async () => {
    const controller = new AbortController();
    controller.abort();
    const findings = await runGraphql(makeTarget(), { signal: controller.signal, timeoutMs: 5000 });
    expect(findings).toHaveLength(0);
    expect(mockSendProbe).not.toHaveBeenCalled();
  });

  it('sends OAST probe when oastCallbackUrl is set', async () => {
    mockSendProbe.mockResolvedValue({ statusCode: 400, body: '', headers: {} });
    await runGraphql(makeTarget(), { ...baseOpts, oastCallbackUrl: 'http://192.168.1.1:7331/oast/abc' });
    // Should have called sendProbe with the oast URL in the payload
    const calls = mockSendProbe.mock.calls;
    const oastCall = calls.find(c => c[0]?.body?.includes('192.168.1.1'));
    expect(oastCall).toBeDefined();
  });
});
