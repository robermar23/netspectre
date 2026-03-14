/**
 * Web Application Security Constants
 * Shared between main and renderer processes.
 * All payloads are static — never assembled from user input.
 */

/** Default proxy port */
export const PROXY_DEFAULT_PORT = 8888;

/** Proxy CA certificate storage directory name */
export const PROXY_CA_DIR = 'proxy-ca';

/** Maximum rows in proxy history DB before pruning */
export const PROXY_HISTORY_MAX_ROWS = 100_000;

/** LRU cache size for dynamic TLS leaf certs */
export const PROXY_CERT_CACHE_SIZE = 200;

/** HTTP ports to treat as web-app pivot targets in the Network workspace */
export const WEB_APP_HTTP_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888];

/** Well-known OpenAPI / Swagger discovery paths */
export const OPENAPI_PATHS = [
  '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
  '/api-docs', '/api-docs.json', '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
  '/api/swagger.json', '/_docs', '/redoc', '/rapidoc',
];

/** Well-known GraphQL endpoint paths */
export const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/gql', '/query'];
