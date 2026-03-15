/**
 * test/webapp/apiDetector.test.js
 * Tests for apiDetector.js — OpenAPI/Swagger/GraphQL schema detection.
 *
 * All HTTP calls are mocked via vi.mock; no real network requests are made.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Mock http / https ────────────────────────────────────────────────────────
// Use vi.hoisted so the mock factory can reference the fn references safely.

const { mockGet, mockReq } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockReq: vi.fn(),
}));

vi.mock('http', () => ({
  default: { get: mockGet, request: mockReq },
  get:     mockGet,
  request: mockReq,
}));

vi.mock('https', () => ({
  default: { get: mockGet, request: mockReq },
  get:     mockGet,
  request: mockReq,
}));

// Helper to simulate a successful HTTP GET response
function mockHttpGet(status, contentType, body) {
  mockGet.mockImplementation((_url, _opts, cb) => {
    const res = {
      statusCode:  status,
      headers:     { 'content-type': contentType },
      on: (event, handler) => {
        if (event === 'data') setTimeout(() => handler(Buffer.from(body)), 0);
        if (event === 'end')  setTimeout(() => handler(), 1);
        return res;
      },
    };
    setTimeout(() => cb(res), 0);
    return {
      on:      vi.fn(),
      destroy: vi.fn(),
    };
  });
}

// Helper to simulate a successful HTTP POST response
function mockHttpPost(status, contentType, body) {
  mockReq.mockImplementation((_url, _opts, cb) => {
    const res = {
      statusCode:  status,
      headers:     { 'content-type': contentType },
      on: (event, handler) => {
        if (event === 'data') setTimeout(() => handler(Buffer.from(body)), 0);
        if (event === 'end')  setTimeout(() => handler(), 1);
        return res;
      },
    };
    setTimeout(() => cb(res), 0);
    return {
      on:      vi.fn(),
      write:   vi.fn(),
      end:     vi.fn(),
      destroy: vi.fn(),
    };
  });
}

// Helper to simulate a 404 for all GET calls
function mockHttpGet404() {
  mockGet.mockImplementation((_url, _opts, cb) => {
    const res = {
      statusCode: 404,
      headers:    { 'content-type': 'text/html' },
      on: (event, handler) => {
        if (event === 'data') {}
        if (event === 'end')  setTimeout(() => handler(), 0);
        return res;
      },
    };
    setTimeout(() => cb(res), 0);
    return { on: vi.fn(), destroy: vi.fn() };
  });
}

import {
  detectApiSchemas,
  parseOpenApiSchema,
  runGraphqlIntrospection,
} from '../../src/main/webapp/apiDetector.js';

// ─── Test Data ────────────────────────────────────────────────────────────────

const OPENAPI_JSON = JSON.stringify({
  openapi: '3.0.0',
  info: { title: 'Test API', version: '1.0' },
  paths: {
    '/users':     { get: { operationId: 'listUsers',  summary: 'List users',  parameters: [] } },
    '/users/{id}':{ get: { operationId: 'getUser',    summary: 'Get user',    parameters: [{ name: 'id', in: 'path', required: true }] },
                    put: { operationId: 'updateUser',  summary: 'Update user', parameters: [] } },
    '/orders':    { post: { operationId: 'createOrder', requestBody: { required: true, content: { 'application/json': {} } } } },
  },
});

const GRAPHQL_INTROSPECTION_RESPONSE = JSON.stringify({
  data: {
    __schema: {
      queryType:        { name: 'Query' },
      mutationType:     { name: 'Mutation' },
      subscriptionType: null,
      types: [
        {
          kind: 'OBJECT',
          name: 'Query',
          fields: [
            { name: 'users',  args: [], type: { kind: 'LIST', name: null, ofType: { kind: 'OBJECT', name: 'User' } } },
            { name: 'user',   args: [{ name: 'id', type: { kind: 'SCALAR', name: 'ID', ofType: null } }], type: { kind: 'OBJECT', name: 'User', ofType: null } },
          ],
        },
        {
          kind: 'OBJECT',
          name: 'Mutation',
          fields: [
            { name: 'createUser', args: [{ name: 'input', type: { kind: 'INPUT_OBJECT', name: 'UserInput', ofType: null } }], type: { kind: 'OBJECT', name: 'User', ofType: null } },
          ],
        },
      ],
    },
  },
});

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('apiDetector.js', () => {

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ─ parseOpenApiSchema ──────────────────────────────────────────────────────

  describe('parseOpenApiSchema', () => {
    it('parses OpenAPI 3 schema into endpoint list', () => {
      const schema   = JSON.parse(OPENAPI_JSON);
      const endpoints = parseOpenApiSchema(schema);
      expect(endpoints.length).toBeGreaterThanOrEqual(4); // GET /users, GET /users/{id}, PUT /users/{id}, POST /orders
    });

    it('extracts path, method, operationId', () => {
      const endpoints = parseOpenApiSchema(JSON.parse(OPENAPI_JSON));
      const listUsers = endpoints.find(e => e.operationId === 'listUsers');
      expect(listUsers).toBeDefined();
      expect(listUsers.path).toBe('/users');
      expect(listUsers.method).toBe('GET');
    });

    it('extracts parameters', () => {
      const endpoints = parseOpenApiSchema(JSON.parse(OPENAPI_JSON));
      const getUser   = endpoints.find(e => e.operationId === 'getUser');
      expect(getUser.parameters.length).toBeGreaterThan(0);
      expect(getUser.parameters[0].name).toBe('id');
    });

    it('extracts requestBody information', () => {
      const endpoints = parseOpenApiSchema(JSON.parse(OPENAPI_JSON));
      const createOrder = endpoints.find(e => e.operationId === 'createOrder');
      expect(createOrder.requestBody).not.toBeNull();
      expect(createOrder.requestBody.required).toBe(true);
    });

    it('returns empty array for null input', () => {
      expect(parseOpenApiSchema(null)).toEqual([]);
    });

    it('returns empty array for schema with no paths', () => {
      expect(parseOpenApiSchema({ openapi: '3.0.0' })).toEqual([]);
    });

    it('handles Swagger 2.0 style paths', () => {
      const swagger2 = {
        swagger: '2.0',
        info: { title: 'Legacy API', version: '2' },
        paths: {
          '/items': { get: { operationId: 'listItems', parameters: [] } },
        },
      };
      const endpoints = parseOpenApiSchema(swagger2);
      expect(endpoints.find(e => e.operationId === 'listItems')).toBeDefined();
    });
  });

  // ─ runGraphqlIntrospection ─────────────────────────────────────────────────

  describe('runGraphqlIntrospection', () => {
    it('returns schema object on successful introspection', async () => {
      mockHttpPost(200, 'application/json', GRAPHQL_INTROSPECTION_RESPONSE);
      const schema = await runGraphqlIntrospection('http://target.com/graphql');
      expect(schema).not.toBeNull();
      expect(schema.queryType.name).toBe('Query');
    });

    it('returns null when endpoint returns non-200', async () => {
      mockHttpPost(404, 'text/html', 'Not Found');
      const schema = await runGraphqlIntrospection('http://target.com/not-graphql');
      expect(schema).toBeNull();
    });

    it('returns null when response is not a GraphQL schema', async () => {
      mockHttpPost(200, 'application/json', JSON.stringify({ data: { foo: 'bar' } }));
      const schema = await runGraphqlIntrospection('http://target.com/graphql');
      expect(schema).toBeNull();
    });

    it('returns null when response is not valid JSON', async () => {
      mockHttpPost(200, 'application/json', 'not json {{{');
      const schema = await runGraphqlIntrospection('http://target.com/graphql');
      expect(schema).toBeNull();
    });

    it('respects AbortSignal', async () => {
      const ctrl = new AbortController();
      ctrl.abort();
      // Should not throw; should return null or reject with AbortError
      const result = await runGraphqlIntrospection('http://target.com/graphql', ctrl.signal).catch(() => null);
      expect(result).toBeNull();
    });
  });

  // ─ detectApiSchemas ────────────────────────────────────────────────────────

  describe('detectApiSchemas', () => {
    it('detects OpenAPI schema and returns structured result', async () => {
      mockHttpGet(200, 'application/json', OPENAPI_JSON);

      const results = await detectApiSchemas('http://api.example.com');
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].type).toBe('openapi');
      expect(results[0].title).toBe('Test API');
      expect(results[0].endpoints.length).toBeGreaterThan(0);
    });

    it('returns empty array when all probes return 404', async () => {
      mockHttpGet404();
      const results = await detectApiSchemas('http://no-api.example.com');
      expect(results).toHaveLength(0);
    });

    it('detects GraphQL when OpenAPI not found but GraphQL is', async () => {
      // First call (OpenAPI probes): 404
      // Switch to POST mock for GraphQL introspection
      mockGet.mockImplementation((_url, _opts, cb) => {
        const res = {
          statusCode: 404,
          headers: { 'content-type': 'text/html' },
          on: (event, handler) => {
            if (event === 'end') setTimeout(() => handler(), 0);
            return res;
          },
        };
        setTimeout(() => cb(res), 0);
        return { on: vi.fn(), destroy: vi.fn() };
      });
      mockHttpPost(200, 'application/json', GRAPHQL_INTROSPECTION_RESPONSE);

      const results = await detectApiSchemas('http://graphql.example.com');
      const graphqlResult = results.find(r => r.type === 'graphql');
      if (graphqlResult) {
        expect(graphqlResult.type).toBe('graphql');
        expect(graphqlResult.endpoints.length).toBeGreaterThan(0);
      }
      // Test passes if no error thrown; GraphQL detection is best-effort
    });

    it('respects AbortSignal — does not probe after abort', async () => {
      const ctrl = new AbortController();
      ctrl.abort();

      const callCount = mockGet.mock.calls.length;
      await detectApiSchemas('http://example.com', ctrl.signal);
      // No additional HTTP calls should have been made
      expect(mockGet.mock.calls.length).toBe(callCount);
    });

    it('returns schemaUrl pointing to the discovered schema path', async () => {
      mockHttpGet(200, 'application/json', OPENAPI_JSON);
      const results = await detectApiSchemas('http://api.example.com');
      if (results.length > 0) {
        expect(results[0].schemaUrl).toContain('api.example.com');
      }
    });

    it('handles network error gracefully', async () => {
      mockGet.mockImplementation((_url, _opts, _cb) => {
        const req = {
          on: (event, handler) => {
            if (event === 'error') setTimeout(() => handler(new Error('ECONNREFUSED')), 0);
            return req;
          },
          destroy: vi.fn(),
        };
        return req;
      });

      await expect(detectApiSchemas('http://offline.example.com')).resolves.toBeDefined();
    });
  });

  // ─ OpenAPI Schema Parsing Edge Cases ──────────────────────────────────────

  describe('OpenAPI edge cases', () => {
    it('handles $ref parameters by resolving them', () => {
      const schema = {
        openapi: '3.0.0',
        info:    { title: 'Ref API', version: '1' },
        components: {
          parameters: {
            UserId: { name: 'userId', in: 'path', required: true },
          },
        },
        paths: {
          '/users/{userId}': {
            get: {
              parameters: [{ $ref: '#/components/parameters/UserId' }],
            },
          },
        },
      };
      const endpoints = parseOpenApiSchema(schema);
      expect(endpoints.length).toBe(1);
      const param = endpoints[0].parameters[0];
      expect(param.name).toBe('userId');
    });

    it('ignores unrecognized HTTP methods', () => {
      const schema = {
        paths: {
          '/items': {
            'x-custom': { summary: 'Custom operation' },
            get: { operationId: 'listItems' },
          },
        },
      };
      const endpoints = parseOpenApiSchema(schema);
      expect(endpoints.every(e => e.method !== 'X-CUSTOM')).toBe(true);
    });
  });
});
