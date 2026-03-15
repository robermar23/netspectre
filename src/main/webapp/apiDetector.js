/**
 * apiDetector.js — API Schema Detection (Feature 7B)
 *
 * Probes well-known OpenAPI/Swagger and GraphQL discovery paths on a target
 * host.  On a successful probe it parses the schema and returns a structured
 * list of endpoints that can be added to the sitemap and sent to the scanner.
 *
 * All network calls are made via Node built-in http/https — zero external
 * HTTP library dependencies.
 */

import http  from 'http';
import https from 'https';
import { URL } from 'url';
import {
  OPENAPI_PATHS,
  GRAPHQL_PATHS,
} from '#shared/webConstants.js';

const REQUEST_TIMEOUT_MS = 8_000;
const MAX_RESPONSE_BYTES = 5_000_000; // 5 MB cap on schema responses

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Probe a base URL for all known OpenAPI and GraphQL endpoints.
 * Respects the provided AbortSignal.
 *
 * @param {string}      baseUrl - e.g. "https://api.example.com"
 * @param {AbortSignal} [signal]
 * @returns {Promise<ApiDetectionResult[]>}
 */
export async function detectApiSchemas(baseUrl, signal) {
  const results = [];

  // OpenAPI / Swagger probes
  for (const probePath of OPENAPI_PATHS) {
    if (signal?.aborted) break;
    const url = _joinUrl(baseUrl, probePath);
    if (!url) continue;
    try {
      const { status, body, contentType } = await _get(url, signal);
      if (status !== 200) continue;
      if (!_isJsonOrYaml(contentType, body)) continue;
      const parsed = _parseOpenApiBody(body, contentType);
      if (!parsed) continue;
      results.push({
        type:      'openapi',
        schemaUrl: url,
        title:     parsed.info?.title ?? 'OpenAPI',
        version:   parsed.info?.version ?? '',
        endpoints: parseOpenApiSchema(parsed),
      });
      break; // found a working path; no need to probe others for this host
    } catch (err) {
      if (err.name === 'AbortError') break;
      // Probe failed (404, timeout, etc.) — try next path
    }
  }

  // GraphQL probes
  for (const probePath of GRAPHQL_PATHS) {
    if (signal?.aborted) break;
    const url = _joinUrl(baseUrl, probePath);
    if (!url) continue;
    try {
      const introspection = await runGraphqlIntrospection(url, signal);
      if (introspection) {
        results.push({
          type:      'graphql',
          schemaUrl: url,
          title:     'GraphQL API',
          version:   '',
          endpoints: _graphqlToEndpoints(introspection, url),
          rawSchema: introspection,
        });
        break;
      }
    } catch (err) {
      if (err.name === 'AbortError') break;
    }
  }

  return results;
}

/**
 * Parse an OpenAPI 2.x / 3.x schema object into a flat endpoint list.
 *
 * @param {Object} schema - Parsed JSON/YAML schema object
 * @returns {ApiEndpoint[]}
 */
export function parseOpenApiSchema(schema) {
  const endpoints = [];
  if (!schema || typeof schema !== 'object') return endpoints;

  const paths = schema.paths ?? schema.apis ?? {};
  for (const [pathStr, pathItem] of Object.entries(paths)) {
    if (typeof pathItem !== 'object') continue;
    const httpMethods = ['get','post','put','patch','delete','head','options','trace'];
    for (const method of httpMethods) {
      const op = pathItem[method];
      if (!op) continue;
      const params = _extractOpenApiParams(op, pathItem, schema);
      endpoints.push({
        path:        pathStr,
        method:      method.toUpperCase(),
        operationId: op.operationId ?? null,
        summary:     op.summary     ?? null,
        parameters:  params,
        requestBody: _extractOpenApiRequestBody(op, schema),
        tags:        op.tags        ?? [],
      });
    }
  }

  return endpoints;
}

/**
 * Send a GraphQL introspection query to `url` and return the parsed type system,
 * or null if the endpoint is not a valid GraphQL server.
 *
 * @param {string}      url
 * @param {AbortSignal} [signal]
 * @returns {Promise<Object|null>}
 */
export async function runGraphqlIntrospection(url, signal) {
  const introspectionQuery = JSON.stringify({
    query: `{
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind name
          fields(includeDeprecated: true) {
            name
            args { name type { kind name ofType { kind name } } }
            type { kind name ofType { kind name } }
          }
        }
      }
    }`,
  });

  try {
    const { status, body } = await _post(url, introspectionQuery, 'application/json', signal);
    if (status !== 200) return null;
    const json = JSON.parse(body);
    if (!json?.data?.__schema) return null;
    return json.data.__schema;
  } catch {
    return null;
  }
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

/**
 * Convert a GraphQL __schema response into a flat endpoint list suitable for
 * the sitemap / scanner.
 */
function _graphqlToEndpoints(schema, schemaUrl) {
  const endpoints = [];
  const { queryType, mutationType, types } = schema;

  for (const typeName of [queryType?.name, mutationType?.name].filter(Boolean)) {
    const typeDef = types?.find(t => t.name === typeName);
    if (!typeDef?.fields) continue;
    const isQuery = typeName === queryType?.name;
    for (const field of typeDef.fields) {
      endpoints.push({
        path:        `${schemaUrl}#${typeName}.${field.name}`,
        method:      isQuery ? 'QUERY' : 'MUTATION',
        operationId: field.name,
        summary:     `GraphQL ${isQuery ? 'query' : 'mutation'}: ${field.name}`,
        parameters:  (field.args ?? []).map(a => ({ name: a.name, in: 'graphql-arg', required: true })),
        requestBody: null,
        tags:        [isQuery ? 'GraphQL Query' : 'GraphQL Mutation'],
      });
    }
  }

  return endpoints;
}

/**
 * Extract parameter definitions from an OpenAPI operation, merging in
 * path-level parameters and resolving $ref references.
 */
function _extractOpenApiParams(operation, pathItem, schema) {
  const merged = [
    ...(pathItem.parameters ?? []),
    ...(operation.parameters ?? []),
  ];
  return merged.map(p => {
    const resolved = _resolveRef(p, schema);
    return {
      name:     resolved.name ?? '',
      in:       resolved.in   ?? 'query',
      required: resolved.required ?? false,
      schema:   resolved.schema   ?? resolved,
    };
  });
}

/**
 * Extract a simplified request body descriptor from an OpenAPI operation.
 */
function _extractOpenApiRequestBody(operation, schema) {
  const rb = operation.requestBody ?? operation.body;
  if (!rb) return null;
  const resolved = _resolveRef(rb, schema);
  const content  = resolved.content ?? {};
  return {
    required:     resolved.required ?? false,
    contentTypes: Object.keys(content),
  };
}

/** Resolve a $ref within the schema (single-level only). */
function _resolveRef(obj, schema) {
  if (!obj || typeof obj !== 'object') return obj ?? {};
  if (!obj.$ref) return obj;
  const ref   = obj.$ref; // e.g. "#/components/parameters/MyParam"
  const parts = ref.replace(/^#\//, '').split('/');
  let   node  = schema;
  for (const part of parts) {
    node = node?.[part];
    if (!node) return obj;
  }
  return node;
}

function _isJsonOrYaml(contentType, body) {
  if (!body || body.length === 0) return false;
  if (contentType.includes('json') || contentType.includes('yaml') || contentType.includes('text/plain')) return true;
  // Sniff for JSON/YAML-looking body even with wrong content-type
  const trimmed = body.trim();
  return trimmed.startsWith('{') || trimmed.startsWith('---') || trimmed.startsWith('swagger:') || trimmed.startsWith('openapi:');
}

/**
 * Parse the response body as OpenAPI JSON or YAML.
 * Only JSON is supported without a YAML library.  YAML is attempted via a
 * minimal regex normalization that handles simple cases.
 */
function _parseOpenApiBody(body, contentType) {
  // Try JSON first
  try {
    const json = JSON.parse(body);
    if (json.swagger || json.openapi || json.paths || json.basePath || json.apis) return json;
  } catch {}

  // Minimal YAML → JSON bridge for simple flat OpenAPI 3 docs
  // A real YAML parser would be needed for production; this handles the common case
  if (contentType.includes('yaml') || body.trim().startsWith('openapi:') || body.trim().startsWith('swagger:')) {
    return _parseSimpleYaml(body);
  }

  return null;
}

/**
 * Very limited YAML parser — only handles scalar key: value pairs and
 * basic nested objects.  Sufficient for extracting info.title and info.version
 * from simple OpenAPI manifests.  Complex schemas with anchors, sequences, etc.
 * will not be fully parsed (we return what we can).
 */
function _parseSimpleYaml(yaml) {
  try {
    const obj   = {};
    const lines = yaml.split(/\r?\n/);
    const stack = [{ indent: -1, obj }];

    for (const line of lines) {
      if (!line.trim() || line.trim().startsWith('#')) continue;
      const indent = line.match(/^(\s*)/)[1].length;
      const match  = line.match(/^(\s*)([^:]+):\s*(.*)?$/);
      if (!match) continue;
      const key   = match[2].trim();
      const value = (match[3] ?? '').trim();

      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
      const parent = stack[stack.length - 1].obj;

      if (value === '' || value === '{}') {
        parent[key] = {};
        stack.push({ indent, obj: parent[key] });
      } else if (value.startsWith('"') || value.startsWith("'")) {
        parent[key] = value.replace(/^["']|["']$/g, '');
      } else {
        parent[key] = isNaN(value) ? value : Number(value);
      }
    }

    return obj;
  } catch {
    return null;
  }
}

/** Join a base URL with a path, returning null on error. */
function _joinUrl(base, path) {
  try {
    return new URL(path, base).href;
  } catch {
    return null;
  }
}

// ─── HTTP Helpers (Node built-ins only) ──────────────────────────────────────

function _get(url, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(Object.assign(new Error('AbortError'), { name: 'AbortError' }));

    const parsed = new URL(url);
    const mod    = parsed.protocol === 'https:' ? https : http;
    const req    = mod.get(url, { timeout: REQUEST_TIMEOUT_MS }, (res) => {
      const chunks   = [];
      let   total    = 0;
      const ctype    = res.headers['content-type'] ?? '';
      res.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) { req.destroy(); return; }
        chunks.push(chunk);
      });
      res.on('end', () => resolve({
        status:      res.statusCode,
        contentType: ctype,
        body:        Buffer.concat(chunks).toString('utf-8'),
      }));
      res.on('error', reject);
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    signal?.addEventListener('abort', () => { req.destroy(); reject(Object.assign(new Error('AbortError'), { name: 'AbortError' })); });
  });
}

function _post(url, body, contentType, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(Object.assign(new Error('AbortError'), { name: 'AbortError' }));

    const parsed  = new URL(url);
    const mod     = parsed.protocol === 'https:' ? https : http;
    const bodyBuf = Buffer.from(body, 'utf-8');
    const options = {
      method:  'POST',
      headers: {
        'Content-Type':   contentType,
        'Content-Length': bodyBuf.length,
        'Accept':         'application/json',
      },
      timeout: REQUEST_TIMEOUT_MS,
    };

    const req = mod.request(url, options, (res) => {
      const chunks = [];
      let   total  = 0;
      res.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) { req.destroy(); return; }
        chunks.push(chunk);
      });
      res.on('end', () => resolve({
        status:      res.statusCode,
        contentType: res.headers['content-type'] ?? '',
        body:        Buffer.concat(chunks).toString('utf-8'),
      }));
      res.on('error', reject);
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    signal?.addEventListener('abort', () => { req.destroy(); reject(Object.assign(new Error('AbortError'), { name: 'AbortError' })); });
    req.write(bodyBuf);
    req.end();
  });
}

/**
 * @typedef {Object} ApiEndpoint
 * @property {string}   path
 * @property {string}   method
 * @property {string|null} operationId
 * @property {string|null} summary
 * @property {Object[]} parameters
 * @property {Object|null} requestBody
 * @property {string[]} tags
 */

/**
 * @typedef {Object} ApiDetectionResult
 * @property {'openapi'|'graphql'} type
 * @property {string}              schemaUrl
 * @property {string}              title
 * @property {string}              version
 * @property {ApiEndpoint[]}       endpoints
 * @property {Object}              [rawSchema]
 */
