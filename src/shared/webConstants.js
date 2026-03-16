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

// ─── Feature 7B — Crawler Constants ──────────────────────────────────────────

/** Maximum crawl depth (hard cap; user cannot exceed this) */
export const CRAWLER_MAX_DEPTH = 10;

/** Maximum pages per active crawl session */
export const CRAWLER_MAX_PAGES = 5000;

/** Default active crawl max depth */
export const CRAWLER_DEFAULT_DEPTH = 3;

/** Default active crawl max pages */
export const CRAWLER_DEFAULT_PAGES = 200;

/** Per-request timeout for active crawler (ms) */
export const CRAWLER_DEFAULT_TIMEOUT_MS = 30_000;

/** Maximum response body size to parse for link extraction (bytes) */
export const CRAWLER_MAX_PARSE_BYTES = 2_000_000;

/** Maximum robots.txt size to fetch (bytes) */
export const ROBOTS_MAX_BYTES = 100_000;

// ─── Feature 7C — Active Vulnerability Scanner Constants ─────────────────────

/** Default scanner concurrency */
export const SCANNER_DEFAULT_CONCURRENCY = 5;

/** Default per-probe timeout (ms) */
export const SCANNER_DEFAULT_TIMEOUT_MS = 10_000;

/** Minimum time-based delay threshold to flag as injection (ms) */
export const SCANNER_TIMING_THRESHOLD_MS = 4_000;

/** URL-like parameter name heuristics for SSRF detection */
export const SSRF_PARAM_NAMES = [
  'url', 'uri', 'link', 'href', 'src', 'redirect', 'callback', 'next',
  'return', 'image', 'file', 'endpoint', 'host', 'domain', 'path', 'dest',
  'destination', 'to', 'location', 'target', 'resource', 'proxy',
];

/** File path parameter name heuristics for LFI/Path Traversal */
export const PATH_PARAM_NAMES = [
  'file', 'path', 'page', 'template', 'doc', 'document', 'include',
  'load', 'read', 'name', 'filename', 'view', 'action', 'dir', 'folder',
];

/** HTTP security headers to audit and their recommended values */
export const SECURITY_HEADERS = [
  { name: 'strict-transport-security', severity: 'high',   label: 'Strict-Transport-Security', recommended: 'max-age=31536000; includeSubDomains' },
  { name: 'content-security-policy',   severity: 'high',   label: 'Content-Security-Policy',   recommended: 'Contextual — see OWASP CSP cheat sheet' },
  { name: 'x-content-type-options',    severity: 'medium', label: 'X-Content-Type-Options',    recommended: 'nosniff' },
  { name: 'x-frame-options',           severity: 'medium', label: 'X-Frame-Options',           recommended: 'DENY or SAMEORIGIN' },
  { name: 'referrer-policy',           severity: 'low',    label: 'Referrer-Policy',           recommended: 'strict-origin-when-cross-origin' },
  { name: 'permissions-policy',        severity: 'low',    label: 'Permissions-Policy',        recommended: 'Restrict geolocation, camera, microphone' },
  { name: 'cross-origin-opener-policy',severity: 'low',    label: 'Cross-Origin-Opener-Policy',recommended: 'same-origin' },
];

/** Database error fingerprints for error-based SQLi detection */
export const DB_ERROR_PATTERNS = [
  { pattern: /you have an error in your sql syntax/i,          db: 'MySQL' },
  { pattern: /mysql_fetch_array\(\)/i,                         db: 'MySQL' },
  { pattern: /unclosed quotation mark after the character string/i, db: 'MSSQL' },
  { pattern: /SqlException/i,                                  db: 'MSSQL' },
  { pattern: /pg_query\(\)/i,                                  db: 'PostgreSQL' },
  { pattern: /ERROR:\s+unterminated/i,                         db: 'PostgreSQL' },
  { pattern: /SQLiteException/i,                               db: 'SQLite' },
  { pattern: /no such column/i,                                db: 'SQLite' },
  { pattern: /ORA-01756/i,                                     db: 'Oracle' },
  { pattern: /quoted string not properly terminated/i,         db: 'Oracle' },
];

/** AWS metadata response keywords for SSRF detection */
export const AWS_METADATA_KEYS = ['ami-id', 'instance-id', 'iam', 'security-credentials', 'local-ipv4'];

/** Severity order for sorting findings (lower index = higher priority) */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// ─── Feature 7E — Out-of-Band & Advanced Detection ───────────────────────────

/** Default OAST HTTP listener port */
export const OAST_DEFAULT_PORT = 7331;

/** OAST token TTL in ms (how long to wait for a callback before discarding the probe) */
export const OAST_TOKEN_TTL_MS = 120_000;

/** Max pending OAST probes tracked simultaneously */
export const OAST_MAX_PENDING = 500;

/** Default WebSocket fuzzer concurrency (simultaneous connections) */
export const WS_FUZZ_DEFAULT_CONCURRENCY = 5;

/** Default per-frame timeout for WebSocket fuzzer (ms) */
export const WS_FUZZ_DEFAULT_TIMEOUT_MS = 8_000;

/** GraphQL introspection probe query */
export const GRAPHQL_INTROSPECTION_QUERY = '{"query":"{__schema{types{name kind}}}"}';

/** GraphQL batch abuse probe — 100 identical queries in one request */
export const GRAPHQL_BATCH_PROBE_COUNT = 100;

/** JWT algorithm values that indicate insecure configuration */
export const JWT_INSECURE_ALGS = ['none', 'None', 'NONE', 'HS1', 'MD5'];

/** Common weak HMAC secrets for JWT brute-force */
export const JWT_WEAK_SECRETS = [
  'secret', 'password', '123456', 'change_me', 'your-256-bit-secret',
  'jwt_secret', 'supersecret', 'mysecret', 'test', 'development',
  'production', 'app_secret', 'token_secret', 'auth_secret', 'key',
];

/** OAuth/OIDC open-redirect test domains */
export const OAUTH_REDIRECT_TEST_DOMAINS = [
  'https://evil.com',
  'https://attacker.example.com',
  '//evil.com',
  '/\\evil.com',
];

/** URL parameter names typically used for redirects (open redirect detection) */
export const REDIRECT_PARAM_NAMES = [
  'redirect', 'redirect_uri', 'redirect_url', 'return', 'returnUrl',
  'return_url', 'next', 'target', 'url', 'goto', 'destination', 'dest',
  'continue', 'forward', 'successUrl', 'failureUrl', 'callback', 'redir',
  'go', 'image_url', 'link', 'ref', 'referer', 'referrer',
];
