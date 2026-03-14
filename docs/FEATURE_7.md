# Feature 7 — Web Application Vulnerability Scanner (Burp Suite Parity)

> **Status:** Planning
> **Branch:** `webapp-scanner`
> **Scope:** Full L7 web application security testing capability integrated into the existing NetSpecter Electron application under a new "Web App" workspace.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Phase Breakdown](#3-phase-breakdown)
4. [Phase 7A — Intercepting HTTP/S Proxy (Foundation)](#4-phase-7a--intercepting-https-proxy-foundation)
5. [Phase 7B — Web Crawling & Attack Surface Mapping](#5-phase-7b--web-crawling--attack-surface-mapping)
6. [Phase 7C — Active Vulnerability Scanner Engine](#6-phase-7c--active-vulnerability-scanner-engine)
7. [Phase 7D — Manual Testing Utilities](#7-phase-7d--manual-testing-utilities)
8. [Phase 7E — Out-of-Band & Advanced Detection](#8-phase-7e--out-of-band--advanced-detection)
9. [Workspace UI Architecture (Feature 10 Integration)](#9-workspace-ui-architecture-feature-10-integration)
10. [IPC Channel Definitions](#10-ipc-channel-definitions)
11. [File & Module Layout](#11-file--module-layout)
12. [Security Constraints](#12-security-constraints)
13. [Test Strategy](#13-test-strategy)
14. [CSS & Theming](#14-css--theming)
15. [Consent & Ethics Gate](#15-consent--ethics-gate)
16. [Implementation Sequence](#16-implementation-sequence)
17. [Dependency Analysis](#17-dependency-analysis)

---

## 1. Executive Summary

NetSpecter today operates at L3/L4 (network and transport layers). Feature 7 adds a full **L7 Web Application Security Testing** workspace that achieves parity with Burp Suite's core capabilities. The workspace is embedded inside the existing Electron application — not a separate product — so users can pivot seamlessly from a discovered host on port 8080 directly into the proxy, repeater, or vulnerability scanner without leaving the app or copying IPs between windows.

### Capability Gap Closure

| Capability | NetSpecter Before | Target After Feature 7 |
|---|---|---|
| HTTP/S Intercepting Proxy | ❌ | ✅ Phase 7A |
| HTTP History Logger | ❌ | ✅ Phase 7A |
| Request Interception & Modification | ❌ | ✅ Phase 7A |
| WebSocket Inspection | ❌ | ✅ Phase 7A |
| Passive Spider / Sitemap | ❌ | ✅ Phase 7B |
| Active Headless Crawler | ❌ | ✅ Phase 7B |
| Content Discovery / Forced Browsing | ✅ (dirFuzzer) | ✅ Integrated Phase 7B |
| API Schema Detection (OpenAPI/Swagger) | ❌ | ✅ Phase 7B |
| SQLi Detection | ❌ | ✅ Phase 7C |
| XSS Detection (Reflected/Stored/DOM) | ❌ | ✅ Phase 7C |
| SSRF Detection | ❌ | ✅ Phase 7C |
| XXE Detection | ❌ | ✅ Phase 7C |
| OS Command Injection | ❌ | ✅ Phase 7C |
| Path Traversal / LFI | ❌ | ✅ Phase 7C |
| CORS Misconfiguration | ❌ | ✅ Phase 7C |
| HTTP Security Header Audit | ❌ | ✅ Phase 7C |
| Broken Authentication Detection | ❌ | ✅ Phase 7C |
| Insecure Deserialization Detection | ❌ | ✅ Phase 7C |
| Repeater (Request Editor) | ❌ | ✅ Phase 7D |
| Intruder (Automated Fuzzer) | ❌ | ✅ Phase 7D |
| Sequencer (Token Entropy) | ❌ | ✅ Phase 7D |
| Decoder/Encoder Workbench | ❌ | ✅ Phase 7D |
| Comparer (Diff Tool) | ❌ | ✅ Phase 7D |
| OAST / Collaborator Callbacks | ❌ | ✅ Phase 7E |
| DOM Invader (Client-Side Tracing) | ❌ | ✅ Phase 7E |
| GraphQL Introspection & Testing | ❌ | ✅ Phase 7E |

---

## 2. Architecture Overview

### Process Separation

```
┌─────────────────────────────────────────────────────────────────┐
│  RENDERER PROCESS                                               │
│  src/renderer/modules/webapp/                                   │
│   ├── proxy.js          ← HTTP History, Intercept toggle        │
│   ├── sitemap.js        ← Passive/Active spider tree view       │
│   ├── scanner.js        ← Vuln scanner controls + findings list │
│   ├── repeater.js       ← Request editor / response viewer      │
│   ├── intruder.js       ← Fuzzer positions + payload config     │
│   ├── sequencer.js      ← Token capture + entropy charts        │
│   ├── decoder.js        ← Encoding workbench                    │
│   └── comparer.js       ← Side-by-side diff view               │
└─────────────────────────────────────────────────────────────────┘
        ↕  contextBridge (preload.js)   ↕
┌─────────────────────────────────────────────────────────────────┐
│  MAIN PROCESS                                                   │
│  src/main/webapp/                                               │
│   ├── proxyServer.js    ← MITM proxy, CA, TLS intercept         │
│   ├── requestStore.js   ← In-memory + SQLite request history    │
│   ├── crawler.js        ← Passive sitemap builder               │
│   ├── activeCrawler.js  ← Puppeteer headless crawler            │
│   ├── apiDetector.js    ← OpenAPI/Swagger/GraphQL detection      │
│   ├── scanner/          ← Vuln scanner engine                   │
│   │   ├── index.js      ← Orchestrator + scan queue             │
│   │   ├── sqli.js       ← SQL Injection module                  │
│   │   ├── xss.js        ← XSS module                           │
│   │   ├── ssrf.js       ← SSRF module                          │
│   │   ├── xxe.js        ← XXE module                           │
│   │   ├── cmdInjection.js                                       │
│   │   ├── pathTraversal.js                                      │
│   │   ├── deserialize.js                                        │
│   │   ├── brokenAuth.js                                         │
│   │   ├── cors.js                                               │
│   │   └── headers.js    ← HTTP security header audit            │
│   ├── intruderEngine.js ← Sniper/BatteringRam/Pitchfork/Bomb    │
│   ├── sequencerEngine.js← Token collection + entropy analysis   │
│   ├── oastServer.js     ← Local DNS/HTTP callback server        │
│   └── ipc/webappIpc.js  ← registerIpcHandlers(ipcMain, getWin) │
└─────────────────────────────────────────────────────────────────┘
        ↕  IPC_CHANNELS (src/shared/ipc.js)  ↕
┌─────────────────────────────────────────────────────────────────┐
│  SHARED                                                         │
│  src/shared/ipc.js       ← New PROXY_*, SCANNER_*, REPEATER_*  │
│  src/shared/webConstants.js ← SQL payloads, XSS canaries, etc. │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Browser (configured with proxy 127.0.0.1:8888)
    ↓ HTTP/HTTPS request
proxyServer.js (MITM, decrypts TLS via dynamic CA)
    ↓ captures { id, request, response, timing }
requestStore.js (SQLite via better-sqlite3)
    ↓ IPC push
renderer/modules/webapp/proxy.js (HTTP History table)
    ↓ user selects request
repeater.js / scanner.js / intruder.js
```

---

## 3. Phase Breakdown

| Phase | Component | Priority | Complexity | Depends On |
|---|---|---|---|---|
| 7A | Intercepting Proxy + History | Critical | Very High | none |
| 7B | Crawler + Attack Surface | High | High | 7A |
| 7C | Active Vuln Scanner | High | Very High | 7A, 7B |
| 7D | Manual Tools (Repeater/Intruder) | High | High | 7A |
| 7E | OAST + DOM Invader + GraphQL | Medium | Very High | 7A, 7C |

Build order: **7A → 7D → 7B → 7C → 7E**. Repeater (7D) is built before the scanner because the scanner reuses the repeater's request-replay core.

---

## 4. Phase 7A — Intercepting HTTP/S Proxy (Foundation)

### 4A.1 — Proxy Server (`src/main/webapp/proxyServer.js`)

#### Certificate Authority Bootstrap

On first launch of the Web App workspace, generate a local Root CA using Node's built-in `crypto` module (no `openssl` binary dependency):

```
~/.config/netspecter/
  └── proxy-ca/
      ├── ca.key   (RSA-2048, persisted across sessions)
      └── ca.crt   (self-signed, 10-year validity)
```

- Use `node-forge` (already a transitive dep via electron-builder) **or** Node's `crypto.generateKeyPairSync` + a minimal X.509 DER encoder for zero new dependencies.
- On first launch, prompt the user to install `ca.crt` into their OS trust store. Provide platform-specific instructions:
  - **Windows:** `certutil -addstore Root ca.crt`
  - **macOS:** `security add-trusted-cert -d -r trustRoot ca.crt`
  - **Linux:** distro-specific (advise manual)
- CA installation is one-click from the settings modal; the IPC handler spawns the certutil command (arg array, never shell string).

#### Dynamic TLS Certificate Generation

For each upstream hostname encountered:

1. Check in-memory LRU cache (`Map<hostname, { cert, key }>`).
2. On cache miss: sign a new leaf certificate with the local CA, valid for 30 days, with `CN=<hostname>` and the matching SAN. Cache it.
3. Use this cert when the client connects via CONNECT tunnel.

Implementation: `crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })` + a minimal X.509 builder, or `node-forge`'s `pki` module.

#### HTTPS CONNECT Tunneling

```
Client --CONNECT hostname:443--> proxyServer
proxyServer -- responds 200 Connection Established
proxyServer -- creates TLS server socket with fake cert
proxyServer -- connects to real upstream as TLS client
proxyServer -- splices decrypted traffic bidirectionally
```

#### WebSocket Interception

After the CONNECT tunnel is established and TLS is decrypted, detect WebSocket upgrades (`Upgrade: websocket` header). Capture each frame (text and binary) into the request store as a `type: 'websocket-frame'` record, including direction (client→server / server→client), timestamp, and raw payload.

#### Proxy Lifecycle

```javascript
// src/main/webapp/proxyServer.js exports:
export function startProxy(port, interceptMode, onRequest, onResponse)
export function stopProxy()
export function setInterceptMode(enabled)
export function forwardInterceptedRequest(id, modifiedRaw)
export function dropInterceptedRequest(id)
export function isProxyRunning()
```

- Default port: `8888` (configurable in settings via electron-store key `proxy.port`).
- `interceptMode: boolean` — when `true`, pause each request and push `PROXY_INTERCEPTED` to renderer before forwarding.
- When intercept is on, store the paused request in a `Map<id, { socket, request }>` pending resolve/drop from renderer.

#### Request Store (`src/main/webapp/requestStore.js`)

- Uses `better-sqlite3` (synchronous, no native addon issues on Electron) to persist HTTP history across sessions.
- DB location: `userData/proxy-history.db`
- Schema:

```sql
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  timestamp INTEGER,
  method TEXT,
  url TEXT,
  host TEXT,
  path TEXT,
  query TEXT,
  status_code INTEGER,
  mime_type TEXT,
  request_headers TEXT,   -- JSON
  request_body BLOB,
  response_headers TEXT,  -- JSON
  response_body BLOB,
  response_length INTEGER,
  duration_ms INTEGER,
  is_websocket INTEGER DEFAULT 0,
  notes TEXT
);

CREATE INDEX idx_host ON requests(host);
CREATE INDEX idx_timestamp ON requests(timestamp DESC);
```

- Maximum 100,000 rows; oldest rows pruned automatically.
- Exports: `insertRequest(r)`, `getRequests(filter)`, `getRequest(id)`, `deleteRequest(id)`, `clearAll()`, `exportHar(ids[])`.

### 4A.2 — IPC Channels for Proxy

```javascript
// src/shared/ipc.js additions (PROXY group)
PROXY_START:            'proxy-start',
PROXY_STOP:             'proxy-stop',
PROXY_STATUS:           'proxy-status',           // main→renderer
PROXY_REQUEST:          'proxy-request',           // main→renderer (new entry)
PROXY_INTERCEPTED:      'proxy-intercepted',       // main→renderer (paused req)
PROXY_FORWARD:          'proxy-forward',           // renderer→main
PROXY_DROP:             'proxy-drop',              // renderer→main
PROXY_SET_INTERCEPT:    'proxy-set-intercept',
PROXY_GET_HISTORY:      'proxy-get-history',
PROXY_GET_REQUEST:      'proxy-get-request',
PROXY_CLEAR_HISTORY:    'proxy-clear-history',
PROXY_INSTALL_CA:       'proxy-install-ca',
PROXY_EXPORT_HAR:       'proxy-export-har',
PROXY_WS_FRAME:         'proxy-ws-frame',          // main→renderer
```

### 4A.3 — Renderer Module (`src/renderer/modules/webapp/proxy.js`)

#### HTTP History Table

Columns: `#` | `Method` | `Host` | `Path` | `Status` | `Length` | `MIME` | `Duration` | `Notes`

- Virtualized rendering using a `<div>`-based virtual scroll (no external library needed; implement a simple fixed-row-height windowing approach), so the table stays responsive with 100k+ rows.
- Clicking a row opens the **Request/Response Inspector** panel below the table.
- Right-click context menu: "Send to Repeater", "Send to Intruder", "Send to Sequencer", "Send to Comparer", "Highlight", "Add Note", "Delete".
- Filter bar (text input + dropdowns) filtering by host, method, status code, MIME type, response length (min/max), and regex match on path or body.

#### Request/Response Inspector

Two-pane split (resizable): left = raw request, right = raw response. Both rendered in a `<pre>` with syntax highlighting for headers (bold) and body (syntax-aware: JSON prettified, HTML decoded). Toggle between "Raw", "Params" (parsed query/POST), "Headers", "Body" views. A "Pretty" vs "Raw" toggle in the body pane.

#### Intercept Panel

When intercept mode is active and a request is paused:

- A pulsing red badge in the workspace tab shows the queue count.
- The intercepted raw request appears in a full-height editable `<textarea>` (monospace, line-wrapping off).
- Buttons: **Forward** (sends possibly-modified request), **Drop**, **Forward All** (disable intercept and flush queue).
- A diff overlay highlights what the user has changed vs. the original.

#### WebSocket History

A separate sub-tab in the proxy panel. Each WS connection is listed; clicking it expands the frame log with direction arrows, timestamps, and payload (text frames rendered as-is; binary frames as hex dump).

### 4A.4 — Consent Gate

Before the proxy starts for the first time, show a modal (mirroring `#pentest-consent-overlay`) explaining: "You are about to start an intercepting proxy that will decrypt TLS traffic. Only test applications you own or have written authorization to test." User must type `I UNDERSTAND` and click Confirm. Decision is stored in `electron-store` key `proxy.consentAccepted`.

---

## 5. Phase 7B — Web Crawling & Attack Surface Mapping

### 5B.1 — Passive Spider (`src/main/webapp/crawler.js`)

The passive spider does not make any new HTTP requests. It processes every request/response that flows through the proxy and builds a URL tree.

```javascript
export function observeRequest(requestRecord)  // called by proxyServer on each request
export function getSitemap()                   // returns tree structure
export function clearSitemap()
export function exportSitemapJson()
```

**What it extracts from each response:**
- All `href`, `src`, `action` attributes from HTML (parse with `node-html-parser`, zero-dep)
- All `<script src>` URLs
- Links found in `Link:` response headers
- URLs in JSON responses that look like API endpoints (regex: `"\/[a-z0-9\-_\/]+"`).
- Form inputs: `name`, `type`, `method`, `action` → stored as attack surface entries.

**Sitemap tree structure:**
```javascript
{
  "example.com": {
    "/": { methods: ["GET"], forms: [], params: [], children: {
      "login": { methods: ["GET","POST"], forms: [{...}], ... },
      "api": { children: { "v1": { children: { "users": {...} } } } }
    }}
  }
}
```

### 5B.2 — Active Headless Crawler (`src/main/webapp/activeCrawler.js`)

Uses **Playwright** (bundled via `playwright-core`; the user must have Chromium/Firefox installed, which is flagged as a soft dependency). Falls back gracefully if Playwright is not available.

```javascript
export async function startActiveCrawl(opts, onUrl, onForm, onComplete, onError)
export function stopActiveCrawl()
```

**`opts` fields:**
```javascript
{
  startUrl: 'https://target.com',
  maxDepth: 3,
  maxPages: 200,
  proxyUrl: 'http://127.0.0.1:8888',  // routes through our proxy!
  includeSubdomains: false,
  submitForms: true,
  clickButtons: true,
  waitForNetworkIdle: true,
  timeoutMs: 30000,
}
```

**Crawler algorithm:**
1. Launch Playwright browser with proxy set to `proxyUrl` (so all traffic flows through our MITM proxy automatically — passive spider gets all discovered URLs for free).
2. BFS queue of `{ url, depth }`.
3. On each page: extract all links, all form `action` targets, all `fetch()` / `XMLHttpRequest` URLs (via `page.on('request')` hook).
4. For form submission: fill text inputs with `"test"`, select first option, submit. Capture the POST request via the proxy.
5. Deduplicate URLs by normalized form (`?a=1&b=2` == `?b=2&a=1`).
6. Respect `robots.txt` (fetch and parse once per domain; skip disallowed paths unless user overrides).
7. Cancel via `AbortController`.

**Soft dependency check:** on `CRAWLER_START` IPC, check if `playwright-core` is installed (`require.resolve` guarded). If not, push `CRAWLER_DEPENDENCY_MISSING` to renderer. The UI will show a "Install Playwright" button that runs `npm install playwright-core --save` in the app's `userData` dir (or advises the user to install it globally).

### 5B.3 — API Schema Detection (`src/main/webapp/apiDetector.js`)

Probes well-known OpenAPI / Swagger / GraphQL discovery paths:

```javascript
const OPENAPI_PATHS = [
  '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
  '/api-docs', '/api-docs.json', '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
  '/api/swagger.json', '/_docs', '/redoc', '/rapidoc',
];
const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/gql', '/query'];
```

For each discovered host, probe these paths (respecting rate limits). On a 200 response:
- Parse the schema to extract all endpoints, methods, and parameters → add to the sitemap as structured attack surface entries.
- For GraphQL: send an introspection query (`{ __schema { queryType { name } types { name fields { name } } } }`) and parse the full type system.
- Surface the schema in the UI as a **tree view** in the Sitemap panel, with each endpoint clickable → "Send to Repeater" / "Scan This Endpoint".

```javascript
export async function detectApiSchemas(baseUrl, signal)
export function parseOpenApiSchema(json)   // returns { endpoints: [...] }
export function runGraphqlIntrospection(url, signal)
```

### 5B.4 — Renderer Module (`src/renderer/modules/webapp/sitemap.js`)

- A collapsible tree view rendered with a recursive `buildTreeNode()` function (no external tree library).
- Each node shows: URL path, HTTP methods seen, count of forms, count of params.
- Color coding: grey = observed only, orange = has forms/params (potential attack surface), red = flagged by scanner.
- Toolbar: "Start Active Crawl" | "Stop" | "Export JSON" | "Clear".
- Active crawl shows a live progress counter (pages visited / max pages) and a spinner.
- A right-click context menu on any node: "Open in Browser", "Send to Scanner", "Send to Repeater", "Send to Dir Fuzzer".

### 5B.5 — IPC Channels for Crawling

```javascript
CRAWLER_START:              'crawler-start',
CRAWLER_STOP:               'crawler-stop',
CRAWLER_URL_FOUND:          'crawler-url-found',         // main→renderer
CRAWLER_FORM_FOUND:         'crawler-form-found',        // main→renderer
CRAWLER_PROGRESS:           'crawler-progress',          // main→renderer
CRAWLER_COMPLETE:           'crawler-complete',          // main→renderer
CRAWLER_ERROR:              'crawler-error',             // main→renderer
CRAWLER_DEPENDENCY_MISSING: 'crawler-dependency-missing',
SITEMAP_GET:                'sitemap-get',
SITEMAP_CLEAR:              'sitemap-clear',
SITEMAP_EXPORT:             'sitemap-export',
API_DETECT:                 'api-detect',
API_SCHEMA_FOUND:           'api-schema-found',          // main→renderer
```

---

## 6. Phase 7C — Active Vulnerability Scanner Engine

### 6C.1 — Scanner Orchestrator (`src/main/webapp/scanner/index.js`)

The orchestrator manages a queue of scan jobs. Each job is `{ target: RequestRecord, modules: string[] }`. The scanner replays the request with modified payloads using the same `httpGet`/`httpPost` pattern from `cloudEnum.js` and `dirFuzzer.js`.

```javascript
export async function startScan(opts, onFinding, onProgress, onComplete, onError)
export function stopScan()
export function isScanRunning()
export function cleanupScan()
```

**`opts` fields:**
```javascript
{
  targets: [{ requestId, url, method, headers, body }], // from proxy history
  modules: ['sqli','xss','ssrf','xxe','cmdInjection','pathTraversal','cors','headers','brokenAuth','deserialize'],
  concurrency: 5,
  timeoutMs: 10000,
  oastCallbackUrl: null,  // from Phase 7E
}
```

**Finding schema:**
```javascript
{
  id: uuid(),
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  type: 'sqli' | 'xss' | ... ,
  title: 'SQL Injection in parameter "id"',
  description: '...',
  url: 'https://target.com/api/users?id=1',
  parameter: 'id',
  payload: "' OR SLEEP(5)--",
  evidence: { request: '...', response: '...', timingMs: 5123 },
  remediation: '...',
  references: ['CWE-89', 'OWASP A03:2021'],
  timestamp: Date.now(),
}
```

**Concurrency:** Reuse the `createSemaphore` pattern from `cloudEnum.js`.

**Cancellation:** Single `AbortController` per scan session.

### 6C.2 — Payload Delivery Helper

All scanner modules share a common `sendProbe(opts, signal)` function that wraps `http`/`https` requests (same pattern as `dirFuzzer.js`) — no external HTTP library. This function:

- Accepts `{ method, url, headers, body, timeoutMs }`.
- Returns `{ statusCode, headers, body, durationMs }`.
- Automatically follows one redirect.
- Never throws on HTTP errors; only throws on network failure or abort.

### 6C.3 — SQL Injection Module (`src/main/webapp/scanner/sqli.js`)

**Input vectors:** query parameters, POST body fields (form-encoded and JSON), Cookie values, headers (`X-Forwarded-For`, `User-Agent`, `Referer`).

**Detection techniques:**

1. **Time-Based Blind:** Inject `'; WAITFOR DELAY '0:0:5'--` (MSSQL), `'; SELECT SLEEP(5)--` (MySQL), `'; SELECT pg_sleep(5)--` (PostgreSQL). If response time > 4.5s (baseline + 3s), flag HIGH. Baseline established by sending a clean request first.

2. **Error-Based:** Inject `'`, `''`, `\`, `1/0`, `1 AND 1=2`. Parse response body for database error strings:
   - MySQL: `You have an error in your SQL syntax`, `mysql_fetch_array()`
   - PostgreSQL: `pg_query()`, `ERROR: unterminated`
   - MSSQL: `Unclosed quotation mark`, `SqlException`
   - SQLite: `SQLiteException`, `no such column`
   - Oracle: `ORA-01756`, `quoted string not properly terminated`
   Flag CRITICAL + detected DB type.

3. **Boolean-Based:** Inject `AND 1=1` (true) and `AND 1=2` (false). If response lengths differ by > 10 bytes consistently, flag MEDIUM.

4. **UNION-Based:** Inject `' UNION SELECT NULL--`, `' UNION SELECT NULL,NULL--` (up to 10 columns). If a 200 response contains `NULL` in an unexpected location, flag HIGH.

**Output:** finding with the DB type fingerprint, the injecting parameter name, the effective payload, and a snippet of the error response as evidence.

**Security note:** Payloads are defined as static string constants in `src/shared/webConstants.js`. They are never assembled via string concatenation with user-supplied data.

### 6C.4 — XSS Module (`src/main/webapp/scanner/xss.js`)

**Canary strategy:** generate a unique `NETSPECTER_<uuid>` string per test. Inject it wrapped in various XSS syntaxes. Check if the raw canary or a variant appears unencoded in the response.

**Reflected XSS payloads:**
```javascript
'<script>alert(1)</script>',
'"><img src=x onerror=alert(1)>',
"'><svg onload=alert(1)>",
'javascript:alert(1)',
'<body onload=alert(1)>',
`<details open ontoggle=alert(1)>`,
```

**Detection:**
1. For each input parameter, inject the canary + XSS syntax.
2. Check if the response body contains the unencoded payload (i.e., `<script>` appears literally in HTML).
3. Also check for partial reflection: if `<script>` is stripped but `alert(1)` appears, flag LOW (potential filter bypass opportunity).
4. DOM-based: if the response contains `.innerHTML`, `.document.write(`, `.location.hash` assignments, flag INFO (manual verification needed).

**Stored XSS:** After a POST that stores data, send a subsequent GET to the likely display page. Check if the canary appears. The crawler's sitemap provides the GET endpoint to verify against.

**Context-aware encoding bypass:** also inject URL-encoded (`%3Cscript%3E`), double-encoded (`%253Cscript%253E`), and Unicode-escaped (`\u003Cscript\u003E`) variants.

### 6C.5 — SSRF Module (`src/main/webapp/scanner/ssrf.js`)

Detect parameters that accept URLs (name heuristics: `url`, `uri`, `link`, `href`, `src`, `redirect`, `callback`, `next`, `return`, `image`, `file`, `endpoint`, `host`, `domain`).

**Probe payloads:**
- Cloud metadata: `http://169.254.169.254/latest/meta-data/`, `http://metadata.google.internal/computeMetadata/v1/`, `http://169.254.169.254/metadata/v1/`
- Localhost services: `http://localhost:6379/` (Redis), `http://localhost:27017/` (MongoDB), `http://127.0.0.1:9200/` (Elasticsearch)
- OAST callback (Phase 7E): `http://<oast-domain>/ssrf-probe-<id>`

**Detection:**
- If response body contains AWS metadata keys (`ami-id`, `instance-id`, `iam`) → flag CRITICAL.
- If response time is significantly higher for internal addresses vs external → flag HIGH (blind SSRF).
- OAST callback received → flag CRITICAL (blind SSRF confirmed).

### 6C.6 — XXE Module (`src/main/webapp/scanner/xxe.js`)

**Targeting:** Only applicable to endpoints that accept XML (Content-Type: `application/xml`, `text/xml`, `application/soap+xml`). Check file upload endpoints that may accept SVG or DOCX (which are XML-based).

**Payloads:**
```xml
<!-- File read -->
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Windows -->
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>

<!-- SSRF via XXE (triggers OAST) -->
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://<oast-domain>/xxe-<id>">]>

<!-- Billion laughs (DoS test — only on user opt-in) -->
```

**Detection:**
- Response contains `root:x:0:0` or `[fonts]` (Windows ini) → CRITICAL.
- OAST callback → CRITICAL.
- XML parser error changes between baseline and injected → MEDIUM (may be exploitable).

### 6C.7 — OS Command Injection (`src/main/webapp/scanner/cmdInjection.js`)

**Payloads (time-based):**
```javascript
'; sleep 5; echo "',
'| sleep 5',
'`sleep 5`',
'; ping -c 5 127.0.0.1;',   // Windows: '| timeout 5'
'$(sleep 5)',
```

**Detection:**
- Response time > baseline + 4s → flag HIGH (time-based blind command injection).
- Response body contains `uid=`, `root`, `WINDOWS` → flag CRITICAL (output reflection).
- OAST callback with `cmdi` prefix → CRITICAL.

### 6C.8 — Path Traversal / LFI (`src/main/webapp/scanner/pathTraversal.js`)

**Target parameters:** `file`, `path`, `page`, `template`, `doc`, `document`, `include`, `load`, `read`, `name`, `filename`.

**Payloads:**
```javascript
'../../etc/passwd',
'../../../etc/passwd',
'....//....//....//etc/passwd',   // filter bypass
'%2e%2e%2f%2e%2e%2fetc/passwd',   // URL encoded
'%252e%252e%252fetc/passwd',       // double encoded
'..%5c..%5cwindows/win.ini',       // Windows backslash
'/etc/passwd',                     // absolute
```

**Detection:**
- Response body matches regex `root:x:0:0:|daemon:x:` → CRITICAL (Unix passwd file).
- Response contains `[fonts]` with `MSDOS=` → CRITICAL (Windows ini).
- Response length is significantly larger than baseline with no error → HIGH (potential LFI).

### 6C.9 — CORS Misconfiguration (`src/main/webapp/scanner/cors.js`)

For every host in the sitemap:

1. Send request with `Origin: https://evil.netspecter.test`.
2. Check response `Access-Control-Allow-Origin`: if it reflects the injected origin → HIGH.
3. If `ACAO: *` AND `Access-Control-Allow-Credentials: true` → CRITICAL (impossible per spec but some frameworks do it).
4. Send `Origin: null` → if `ACAO: null` returned → HIGH.
5. Send `Origin: https://target.com.evil.test` → if reflected → CRITICAL.

### 6C.10 — HTTP Security Headers (`src/main/webapp/scanner/headers.js`)

Check every response (passively via proxy, no extra requests needed) for missing security headers:

| Header | Severity If Missing | Recommended Value |
|---|---|---|
| `Strict-Transport-Security` | HIGH | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | HIGH | Contextual — flag absence |
| `X-Content-Type-Options` | MEDIUM | `nosniff` |
| `X-Frame-Options` | MEDIUM | `DENY` or `SAMEORIGIN` |
| `Referrer-Policy` | LOW | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | LOW | Flag absence |
| `Cross-Origin-Opener-Policy` | LOW | `same-origin` |

Also check for **dangerous header values:**
- `Server: Apache/2.2.3` → flag INFO (version disclosure).
- `X-Powered-By: PHP/5.4` → flag INFO.
- `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` → CRITICAL.
- `Set-Cookie` missing `HttpOnly` → MEDIUM per cookie.
- `Set-Cookie` missing `Secure` on HTTPS → MEDIUM.
- `Set-Cookie` missing `SameSite` → LOW.

### 6C.11 — Broken Authentication (`src/main/webapp/scanner/brokenAuth.js`)

1. **Rate limit detection:** Replay a login form POST 20 times with bad credentials. If all 20 succeed without a 429 or CAPTCHA → flag HIGH (no rate limiting).
2. **Username enumeration:** Send requests with valid vs. invalid usernames. Compare response body length and timing. If delta > 50 bytes or 200ms → flag MEDIUM.
3. **Cookie attribute audit:** (Merged from `headers.js` — see above.)
4. **Weak password policy probe:** Attempt login with `password: "password"`, `password: "123456"`. If login succeeds → CRITICAL (predictable default/weak credentials).
5. **JWT inspection:** Detect JWTs in cookies, Authorization headers, or response bodies. Parse header + payload (no signature verification needed). Flag:
   - `alg: none` → CRITICAL.
   - `alg: HS256` with a long secret key (can't test without key) → INFO.
   - Expiry (`exp`) > 7 days → LOW.
   - Missing `aud` or `iss` claims → INFO.

### 6C.12 — Insecure Deserialization (`src/main/webapp/scanner/deserialize.js`)

**Detection (passive, no exploitation):**

1. Detect serialized data in cookies, POST bodies, or JSON fields:
   - PHP: `O:n:"ClassName":{...}` → flag INFO with advisory.
   - Java: `rO0AB` (Base64-encoded `aced 0005` magic bytes) → flag INFO.
   - Python Pickle: `\x80\x02` prefix → flag INFO.
   - .NET `__VIEWSTATE` without `enableViewStateMac` → flag MEDIUM.
2. For Java-detected objects: optionally send a known ysoserial `CommonsCollections1` gadget chain DNS-lookup payload pointing to the OAST server. If OAST receives a DNS lookup → CRITICAL.
3. Never send memory-corrupting payloads. The goal is detection, not weaponization.

### 6C.13 — Scanner Renderer Module (`src/renderer/modules/webapp/scanner.js`)

**Scan Configuration Panel:**
- Target selection: checkboxes over sitemap endpoints, OR "Scan All History", OR paste a URL.
- Module selection: toggle each of the 10 scan modules on/off.
- Concurrency slider (1–20).
- Timeout input.
- OAST toggle (if Phase 7E is available).

**Findings Table:**
- Columns: Severity badge | Type | Title | URL | Parameter | Timestamp.
- Sorted by severity (Critical first).
- Color-coded severity badges matching the glassmorphic theme: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue, INFO=grey.
- Click a finding row → expand to show: Description, Evidence (request/response raw), Remediation, CWE/OWASP reference.
- "Send to Repeater" button on each finding (pre-fills repeater with the vulnerable request + payload).

**Progress bar + scan summary:** "Tested 47 / 200 endpoints — 3 Critical, 5 High, 12 Medium found."

**Export:** JSON, CSV, or HTML report (inline CSS report for easy sharing).

### 6C.14 — IPC Channels for Scanner

```javascript
SCANNER_START:      'scanner-start',
SCANNER_STOP:       'scanner-stop',
SCANNER_FINDING:    'scanner-finding',    // main→renderer
SCANNER_PROGRESS:   'scanner-progress',  // main→renderer
SCANNER_COMPLETE:   'scanner-complete',  // main→renderer
SCANNER_ERROR:      'scanner-error',     // main→renderer
SCANNER_GET_FINDINGS: 'scanner-get-findings',
SCANNER_EXPORT:     'scanner-export',
SCANNER_CLEAR:      'scanner-clear',
```

---

## 7. Phase 7D — Manual Testing Utilities

### 7D.1 — Repeater (`src/renderer/modules/webapp/repeater.js` + `src/main/webapp/repeaterEngine.js`)

The Repeater is a standalone request editor and replay tool. It is self-contained in the renderer (for UI) with only a thin main-process relay for sending the actual HTTP request (to avoid CORS restrictions in the renderer).

**UI Layout:**
```
┌──────────────────┬──────────────────────────────────┐
│ Request Editor   │ Response Viewer                   │
│ (editable)       │ (read-only)                       │
│                  │                                   │
│ GET /api/users   │ HTTP/1.1 200 OK                   │
│ Host: target.com │ Content-Type: application/json    │
│ ...              │                                   │
│                  │ { "users": [...] }                │
├──────────────────┴──────────────────────────────────┤
│ [Send] [Cancel] [←] [→] (history navigation)        │
└─────────────────────────────────────────────────────┘
```

- **Request editor:** plain `<textarea>` with line-number gutter. Monospace. Syntax: first line is the request line (`METHOD PATH HTTP/1.1`), followed by headers, blank line, body. Editable character by character.
- **Response viewer:** read-only raw display with optional "Pretty" toggle (JSON prettified, HTML rendered in a sandboxed `<iframe>`).
- **History:** each "Send" push is saved in a session array. `←` / `→` navigate between previous and next versions of the request (like Burp's request history in Repeater).
- **Tabs:** support multiple independent Repeater tabs (requests come from different "Send to Repeater" actions). Tab bar with `+` button and `×` close per tab.
- The renderer sends `REPEATER_SEND` IPC; the main process relay (`repeaterEngine.js`) fires the HTTP request (bypassing browser CORS), and returns the raw response.

**IPC:**
```javascript
REPEATER_SEND:     'repeater-send',
REPEATER_RESPONSE: 'repeater-response',  // main→renderer
REPEATER_ERROR:    'repeater-error',     // main→renderer
```

**Main-side `repeaterEngine.js`:** wraps `sendProbe()` from the scanner. Validates that the target URL passes the same allowlist check used in dirFuzzer. Returns `{ statusCode, headers, body, durationMs, rawRequest, rawResponse }`.

### 7D.2 — Intruder (`src/renderer/modules/webapp/intruder.js` + `src/main/webapp/intruderEngine.js`)

The Intruder automates sending many variations of a request template.

**Payload position marking:** User pastes a raw HTTP request into the editor. They select a substring and click "Mark Position" to wrap it in `§markers§`. Multiple positions supported.

**Attack types:**
- **Sniper:** One position at a time. Payload list iterates through position 1, then position 2, etc.
- **Battering Ram:** Single payload list applied to ALL positions simultaneously (same value).
- **Pitchfork:** N payload lists, each mapped to one position. Iterates in parallel (row 1 of list 1 + row 1 of list 2 → one request).
- **Cluster Bomb:** Cartesian product. Every combination of every payload across all positions.

**Payload sources:**
- Simple list (paste in textarea, one per line).
- Load from file (dialog → `BROWSE_FILE` IPC).
- Built-in wordlists: `common-passwords.txt` (top 1000), `usernames.txt`, `sqli-payloads.txt`, `xss-payloads.txt` (shipped in `resources/wordlists/`).
- Payload processing: prefix, suffix, URL encode, Base64 encode, reverse, uppercase (chainable transforms).

**Results table:**
- Columns: `#` | `Payload(s)` | `Status` | `Length` | `Duration` | `Error?`
- Sortable by any column.
- Right-click → "Send to Repeater", "Highlight".
- Color-coded status (same as dirFuzzer): 200=green, 3xx=blue, 4xx=orange, 5xx=red.

**Rate limiting:** configurable delay between requests (ms) and max concurrency.

**IPC:**
```javascript
INTRUDER_START:    'intruder-start',
INTRUDER_STOP:     'intruder-stop',
INTRUDER_RESULT:   'intruder-result',   // main→renderer (one per request)
INTRUDER_PROGRESS: 'intruder-progress', // main→renderer
INTRUDER_COMPLETE: 'intruder-complete',
INTRUDER_ERROR:    'intruder-error',
```

**Main-side:** `intruderEngine.js` expands positions against the payload matrix, fires requests via `sendProbe()`, emits results via `webContents.send()`. Semaphore-based concurrency. `AbortController` for stop.

### 7D.3 — Sequencer (`src/renderer/modules/webapp/sequencer.js` + `src/main/webapp/sequencerEngine.js`)

Analyzes the randomness quality of tokens (session cookies, CSRF tokens, password reset links).

**Token capture modes:**
1. **Live capture from proxy:** user selects a Set-Cookie header or response field from HTTP history. The sequencer sends that same request N times via the main process, collecting a fresh token each time.
2. **Manual paste:** user pastes a list of tokens (one per line).

**Analysis (runs entirely in main process on a worker thread to avoid blocking):**
- Sample size: minimum 100 tokens, recommended 300+.
- Extract the varying bits: XOR all tokens together to find which bit positions change.
- **FIPS 140-2 tests:** monobit test, frequency block test, runs test, longest run test. Implement these directly in JS — they are well-defined bitwise algorithms.
- **Chi-squared test** on byte frequency distribution.
- **Entropy calculation:** Shannon entropy (bits per byte) of the effective bits.
- **Spectral test (FFT):** detect repeating patterns using a DFT on the bit sequence.

**Results display:**
- Entropy score (0–8 bits per byte). Green if > 6.5, yellow if 4–6.5, red if < 4.
- Pass/fail per FIPS test.
- Visual histogram of byte frequency.
- A summary verdict: "STRONG — token appears cryptographically random" or "WEAK — token has predictable patterns" + remediation advice.

**IPC:**
```javascript
SEQUENCER_COLLECT:  'sequencer-collect',   // renderer→main: start collecting N tokens
SEQUENCER_TOKEN:    'sequencer-token',     // main→renderer: one captured token
SEQUENCER_ANALYZE:  'sequencer-analyze',  // renderer→main: analyze a token list
SEQUENCER_RESULT:   'sequencer-result',   // main→renderer: analysis output
SEQUENCER_ERROR:    'sequencer-error',
```

### 7D.4 — Decoder (`src/renderer/modules/webapp/decoder.js`)

A pure renderer-side utility (no IPC needed — all encoding/decoding is synchronous JS).

**Supported transforms (each is a separate tab or chainable):**
- Base64 encode / decode
- URL encode (`encodeURIComponent`) / decode
- HTML entity encode / decode (`&amp;` `&lt;` etc.)
- Hex encode / decode (bytes to hex string)
- Gzip compress / decompress (using `pako` or Node's `zlib` via IPC)
- JWT decode (header + payload JSON, no signature verification)
- Unicode escape (`\uXXXX`) encode / decode
- MD5 / SHA-1 / SHA-256 hash (using `crypto.subtle` in renderer or `crypto` in main via IPC)

**Chain mode:** The output of transform A is fed as the input to transform B. Chain up to 10 transforms. Visualized as a pipeline with arrows.

**Input:** Large `<textarea>` on the left. Output: read-only `<textarea>` on the right. Automatically re-runs the chain on any input change (debounced 300ms).

**IPC (only for Gzip and Hash):**
```javascript
DECODER_TRANSFORM: 'decoder-transform',  // renderer→main
DECODER_RESULT:    'decoder-result',     // main→renderer
```

### 7D.5 — Comparer (`src/renderer/modules/webapp/comparer.js`)

Side-by-side diff of two HTTP requests or responses.

**Input:** drag a row from HTTP History into "Side A" or "Side B" slots, or paste raw text.

**Diff algorithm:** Implement Myers diff algorithm (standard O(ND) diff) in pure JS — no external library. Highlight added bytes in green, removed in red, unchanged in grey.

**Display modes:**
- **Word diff** (default): highlights changed words/tokens.
- **Line diff**: highlights entire changed lines.
- **Byte diff**: for binary/hex payloads.

**Statistics panel:** bytes added, bytes removed, % similarity, total lines different.

**Use cases surfaced in UI:** "Compare two login responses to find enumeration differences", "Compare scanner baseline vs. payload response".

No IPC needed — pure renderer computation.

---

## 8. Phase 7E — Out-of-Band & Advanced Detection

### 8E.1 — OAST Server (`src/main/webapp/oastServer.js`)

A local DNS resolver and HTTP callback server that receives out-of-band interactions from injected payloads. Equivalent to Burp Collaborator or `interactsh`, but running entirely locally.

**DNS callback:**
- Spawn a local UDP DNS server on port 53 (requires elevated privileges; fallback: use a random high port and note the limitation).
- Generate a unique subdomain prefix per scan: `<uuid>.oast.local`.
- Resolve all queries for `*.oast.local` to `127.0.0.1`.
- Record each DNS query that arrives: `{ id, subdomain, queryType, sourceIp, timestamp }`.
- On privilege failure (EACCES on port 53): use a localhost-only workaround — inject `http://<oast-http-url>` instead of DNS. Full DNS OAST only works with elevated privileges or on Linux with `CAP_NET_BIND_SERVICE`.

**HTTP callback:**
- Local HTTP server on a random available port (e.g., 19876).
- Each callback URL format: `http://127.0.0.1:19876/oast/<id>/<label>`.
- On request arrival: emit `OAST_CALLBACK` to renderer with `{ id, label, method, path, headers, body, sourceIp, timestamp }`.

**Integration with scanner:** Each scanner module receives the `oastCallbackUrl` in `opts`. For blind payloads (blind SSRF, blind XXE, blind SQLi, blind CMDi), the module embeds a unique OAST URL in the payload. When the callback arrives, the scanner correlates it back to the originating finding and upgrades it to CRITICAL.

```javascript
export function startOastServer(onCallback)
export function stopOastServer()
export function generateCallbackUrl(label)  // returns { url, id }
export function pollCallbacks(id, timeoutMs) // returns Promise<callback | null>
```

**IPC:**
```javascript
OAST_START:    'oast-start',
OAST_STOP:     'oast-stop',
OAST_CALLBACK: 'oast-callback',   // main→renderer
OAST_STATUS:   'oast-status',     // main→renderer
```

### 8E.2 — DOM Invader (`src/main/webapp/domInvader.js`)

A JavaScript agent that is injected into pages browsed through the proxy to trace DOM sources and sinks in real time.

**How it works:**
- The proxy server's `proxyServer.js` inspects every HTML response. If the Content-Type is `text/html`, it injects a `<script>` tag before `</head>` (or as the first child of `<body>`) that loads `dom-invader-agent.js`.
- `dom-invader-agent.js` is a small file served by the local OAST HTTP server.

**What the agent instruments:**
- **Sources:** `location.search`, `location.hash`, `document.cookie`, `document.referrer`, `window.name`, `postMessage` listener registration.
- **Sinks:** `.innerHTML`, `.outerHTML`, `document.write()`, `document.writeln()`, `eval()`, `setTimeout(string)`, `setInterval(string)`, `.src` assignment on `<script>` elements, `location.href` assignment.
- **Prototype pollution:** `Object.prototype.__proto__` assignments, `Object.assign` with user-controlled keys.

**Detection:** When the agent detects data flowing from a source to a dangerous sink, it sends a beacon to `http://127.0.0.1:<oastPort>/dom-invader/<finding-id>` with the source, sink, value, and stack trace. The main process receives this, creates a DOM XSS finding, and pushes `SCANNER_FINDING` to the renderer.

**Injection safety:** The agent is injected ONLY when the proxy is active, the user has consented, and the host is within the user-defined target scope. The agent is a self-contained IIFE with no global namespace pollution beyond its own sentinel variable.

**IPC:** Handled via `OAST_CALLBACK` (same callback server).

### 8E.3 — GraphQL Testing (`src/main/webapp/apiDetector.js` extension)

Once a GraphQL endpoint is detected (see 5B.3), additional active tests are run:

1. **Introspection enabled:** If `__schema` is returned → INFO (helps attackers map the API). Should be disabled in production.
2. **Authorization bypass:** Run the same query with no `Authorization` header. If private fields are returned → CRITICAL.
3. **Injection in arguments:** For each string argument in the schema, inject SQLi and XSS payloads. Same detection logic as modules 6C.3 and 6C.4.
4. **Batch query abuse:** Send a batched query array with 100 identical operations. If all succeed → flag HIGH (no rate limiting on batch queries).
5. **Field suggestion:** Send a query with a slightly misspelled field name. If the response contains `"Did you mean ..."` → flag INFO (introspection leakage via suggestions).
6. **Excessive data exposure:** Request all fields on a type. Compare response size to the size when only a few fields are requested. If the server returns fields the client didn't request → flag HIGH.

---

## 9. Workspace UI Architecture (Feature 10 Integration)

Feature 7 is built to live inside a multi-workspace UI as described in Feature 10 of the brainstorm document.

### 9.1 — Workspace Switcher

Add a top-level tab bar to `index.html`:

```html
<nav id="workspace-bar">
  <button class="workspace-tab active" data-workspace="network">
    🌐 Network
  </button>
  <button class="workspace-tab" data-workspace="webapp">
    🕷️ Web App
  </button>
  <button class="workspace-tab" data-workspace="utilities">
    🔧 Utilities
  </button>
</nav>
```

The workspace switcher shows/hides the appropriate `<section id="ws-network">` / `<section id="ws-webapp">` / `<section id="ws-utilities">` containers via CSS class toggle. No re-rendering; each workspace is pre-rendered in the DOM and toggled with `display: none / flex`.

### 9.2 — Web App Workspace Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  🌐 Network  |  🕷️ Web App  |  🔧 Utilities                   │
├──────────────┬──────────────────────────────────────────────────┤
│  Proxy       │  [Proxy controls bar]  Target: _____ Port: ___   │
│  Sitemap     │  [Intercept toggle] [CA Install] [Clear History]  │
│  Scanner     ├──────────────────────────────────────────────────┤
│  Repeater    │                                                   │
│  Intruder    │   Main content area (switches per sidebar item)   │
│  Sequencer   │                                                   │
│  Decoder     │                                                   │
│  Comparer    │                                                   │
│  Findings    │                                                   │
└──────────────┴──────────────────────────────────────────────────┘
```

The left sidebar is a vertical icon+label nav (like VS Code's Activity Bar). Clicking each item swaps the main content area. The sidebar is narrow (48px collapsed, 160px expanded) with a toggle.

### 9.3 — Pivot from Network Workspace

In the Network workspace, when the user right-clicks on a host card (or clicks the host details panel):
- If any open ports are HTTP/HTTPS ports (80, 443, 8080, 8443, 3000, 5000, 8000, 8888): show a "🕷️ Open in Web App" button.
- Clicking it: switches to the Web App workspace, pre-fills the target URL with `http(s)://<ip>:<port>`, and optionally starts the active crawler.
- This uses a `window.__openWebAppWorkspace(url)` global exposed from `webapp/proxy.js` init, which is the same pattern used by `window.__openDirFuzzPanel(url)` and `window.__openSharePanel(ip)`.

### 9.4 — Shared Data Layer

The host objects in `state.hosts[]` are accessible to the Web App workspace. The scanner writes its findings back to the same `state` object (a new `state.webAppFindings[]` array). When a finding contains a hostname/IP that matches an entry in `state.hosts[]`, a **"⚠️ Web Vulnerabilities"** badge is added to that host's card in the Network workspace. This creates the bidirectional pivot: Network → Web App → findings surfaced back in Network.

---

## 10. IPC Channel Definitions

All new channels added to `src/shared/ipc.js`:

```javascript
// ─── Feature 7A — Intercepting Proxy ────────────────────────────────────────
PROXY_START:                'proxy-start',
PROXY_STOP:                 'proxy-stop',
PROXY_STATUS:               'proxy-status',
PROXY_REQUEST:              'proxy-request',
PROXY_INTERCEPTED:          'proxy-intercepted',
PROXY_FORWARD:              'proxy-forward',
PROXY_DROP:                 'proxy-drop',
PROXY_SET_INTERCEPT:        'proxy-set-intercept',
PROXY_GET_HISTORY:          'proxy-get-history',
PROXY_GET_REQUEST:          'proxy-get-request',
PROXY_CLEAR_HISTORY:        'proxy-clear-history',
PROXY_INSTALL_CA:           'proxy-install-ca',
PROXY_EXPORT_HAR:           'proxy-export-har',
PROXY_WS_FRAME:             'proxy-ws-frame',

// ─── Feature 7B — Crawler & Attack Surface ───────────────────────────────────
CRAWLER_START:              'crawler-start',
CRAWLER_STOP:               'crawler-stop',
CRAWLER_URL_FOUND:          'crawler-url-found',
CRAWLER_FORM_FOUND:         'crawler-form-found',
CRAWLER_PROGRESS:           'crawler-progress',
CRAWLER_COMPLETE:           'crawler-complete',
CRAWLER_ERROR:              'crawler-error',
CRAWLER_DEPENDENCY_MISSING: 'crawler-dep-missing',
SITEMAP_GET:                'sitemap-get',
SITEMAP_CLEAR:              'sitemap-clear',
SITEMAP_EXPORT:             'sitemap-export',
API_DETECT:                 'api-detect',
API_SCHEMA_FOUND:           'api-schema-found',

// ─── Feature 7C — Active Scanner ─────────────────────────────────────────────
SCANNER_START:              'scanner-start',
SCANNER_STOP:               'scanner-stop',
SCANNER_FINDING:            'scanner-finding',
SCANNER_PROGRESS:           'scanner-progress',
SCANNER_COMPLETE:           'scanner-complete',
SCANNER_ERROR:              'scanner-error',
SCANNER_GET_FINDINGS:       'scanner-get-findings',
SCANNER_EXPORT:             'scanner-export',
SCANNER_CLEAR:              'scanner-clear',

// ─── Feature 7D — Manual Tools ───────────────────────────────────────────────
REPEATER_SEND:              'repeater-send',
REPEATER_RESPONSE:          'repeater-response',
REPEATER_ERROR:             'repeater-error',

INTRUDER_START:             'intruder-start',
INTRUDER_STOP:              'intruder-stop',
INTRUDER_RESULT:            'intruder-result',
INTRUDER_PROGRESS:          'intruder-progress',
INTRUDER_COMPLETE:          'intruder-complete',
INTRUDER_ERROR:             'intruder-error',

SEQUENCER_COLLECT:          'sequencer-collect',
SEQUENCER_TOKEN:            'sequencer-token',
SEQUENCER_ANALYZE:          'sequencer-analyze',
SEQUENCER_RESULT:           'sequencer-result',
SEQUENCER_ERROR:            'sequencer-error',

DECODER_TRANSFORM:          'decoder-transform',
DECODER_RESULT:             'decoder-result',

// ─── Feature 7E — OAST / DOM Invader / GraphQL ───────────────────────────────
OAST_START:                 'oast-start',
OAST_STOP:                  'oast-stop',
OAST_CALLBACK:              'oast-callback',
OAST_STATUS:                'oast-status',
```

All new channels follow the existing naming convention: `NOUN_VERB` for renderer→main, `NOUN_EVENT` for main→renderer pushes.

---

## 11. File & Module Layout

```
src/
├── main/
│   └── webapp/
│       ├── proxyServer.js        [7A] MITM proxy, CA, TLS, WebSocket
│       ├── requestStore.js       [7A] SQLite history (better-sqlite3)
│       ├── crawler.js            [7B] Passive spider
│       ├── activeCrawler.js      [7B] Playwright headless crawler
│       ├── apiDetector.js        [7B,7E] OpenAPI / GraphQL detection
│       ├── scanner/
│       │   ├── index.js          [7C] Orchestrator
│       │   ├── probe.js          [7C] sendProbe() shared helper
│       │   ├── sqli.js           [7C] SQL Injection
│       │   ├── xss.js            [7C] XSS
│       │   ├── ssrf.js           [7C] SSRF
│       │   ├── xxe.js            [7C] XXE
│       │   ├── cmdInjection.js   [7C] OS Command Injection
│       │   ├── pathTraversal.js  [7C] LFI / Path Traversal
│       │   ├── deserialize.js    [7C] Insecure Deserialization
│       │   ├── brokenAuth.js     [7C] Auth Testing
│       │   ├── cors.js           [7C] CORS
│       │   └── headers.js        [7C] Security Headers
│       ├── repeaterEngine.js     [7D] HTTP request relay
│       ├── intruderEngine.js     [7D] Payload matrix + request firing
│       ├── sequencerEngine.js    [7D] Token collection + entropy
│       ├── oastServer.js         [7E] DNS + HTTP callback server
│       ├── domInvaderAgent.js    [7E] Injected JS agent (served statically)
│       └── ipc/
│           └── webappIpc.js      registerIpcHandlers(ipcMain, getWindow)
│
├── renderer/
│   └── modules/
│       └── webapp/
│           ├── index.js          init() + sidebar routing
│           ├── proxy.js          [7A] HTTP History table + Intercept UI
│           ├── sitemap.js        [7B] Tree view
│           ├── scanner.js        [7C] Scanner config + findings list
│           ├── repeater.js       [7D] Repeater tabs + editor
│           ├── intruder.js       [7D] Position marker + payload config + results
│           ├── sequencer.js      [7D] Token capture + entropy charts
│           ├── decoder.js        [7D] Encoding chain workbench
│           └── comparer.js       [7D] Myers diff view
│
├── shared/
│   ├── ipc.js                    + new channel constants (section 10)
│   └── webConstants.js           [NEW] payloads, canaries, wordlists refs
│
resources/
└── wordlists/
    ├── common-passwords.txt      top 1000 passwords
    ├── usernames.txt             common usernames
    ├── sqli-payloads.txt         curated SQLi payload list
    └── xss-payloads.txt          curated XSS payload list

test/
├── webapp/
│   ├── proxyServer.test.js
│   ├── requestStore.test.js
│   ├── crawler.test.js
│   ├── scanner/
│   │   ├── sqli.test.js
│   │   ├── xss.test.js
│   │   ├── ssrf.test.js
│   │   ├── xxe.test.js
│   │   ├── cors.test.js
│   │   ├── headers.test.js
│   │   └── brokenAuth.test.js
│   ├── intruderEngine.test.js
│   └── sequencerEngine.test.js
└── renderer/
    └── webapp/
        ├── proxy.test.js
        ├── scanner.test.js
        ├── decoder.test.js
        └── comparer.test.js
```

---

## 12. Security Constraints

These constraints are **non-negotiable** and must be reviewed before each module is merged.

### 12.1 — Input Validation

| Input Point | Validation Rule |
|---|---|
| Proxy target URL | Must be `http://` or `https://`; reject `file://`, `data://`, `javascript:` |
| Proxy listen port | Integer 1024–65535 only; reject OS privileged ports |
| Intruder payload count | Hard cap at 1,000,000 total requests per session |
| Crawler max depth | Hard cap at 10; user cannot set higher |
| Repeater target URL | Same URL validation as dirFuzzer (`ALLOWED_SCHEMES`) |
| Scanner concurrency | Max 50 (same as dirFuzzer) |
| wordlist file size | Max 500,000 lines; reject binary files |

### 12.2 — Spawn Safety

- `proxyServer.js` installs the CA cert by spawning `certutil` (Windows) with arg arrays. The cert path is validated to be within `userData` before passing to certutil.
- Active crawler (Playwright): Playwright is not spawned with shell-string args. The `executablePath` comes from `playwright-core`'s own resolution, not user input.
- OAST DNS server: runs inside the Node.js process (no spawn); uses `dgram.createSocket('udp4')`.

### 12.3 — Data Handling

- HTTP request/response bodies are stored as BLOB in SQLite. They are never echoed back via `eval()` or injected into the DOM without escaping.
- The HTTP History table renders all content as text (`.textContent`, never `.innerHTML`) to prevent stored XSS from captured content affecting the app's own UI.
- The Repeater response viewer renders HTML responses in a sandboxed `<iframe>` with `sandbox="allow-scripts"` when the user clicks "Render". The iframe has no access to the Electron `preload` context.
- Payloads defined in `webConstants.js` are static arrays — never constructed from user-controlled strings.

### 12.4 — Proxy Scope Restriction

- The user defines a **target scope** (list of hostnames/CIDR ranges). The proxy only logs and intercepts in-scope traffic. Out-of-scope traffic is passed through transparently without logging.
- The scanner and intruder will only send requests to in-scope targets. Out-of-scope URLs are rejected before `sendProbe()` is called.
- Scope is persisted in `electron-store` as `proxy.scope: string[]`.

### 12.5 — Consent Gates

Two consent gates are required:

1. **Proxy Consent** (first proxy start): explains MITM nature, TLS decryption. Stored in `proxy.consentAccepted`.
2. **Active Scanner Consent** (first scan start): explains automated vulnerability testing. Stored in `scanner.consentAccepted`. Requires the user to confirm the target is within their authorization scope.

---

## 13. Test Strategy

### Coverage Targets

- Main-process modules: ≥ 80% line coverage (Vitest).
- Renderer modules: ≥ 70% (Vitest + jsdom).
- Integration: manual test script covering proxy → history → scanner → repeater round-trip.

### Test Patterns

Follow the existing test pattern from `test/nmapScanner.test.js` and `test/cloudEnum.test.js`:

```javascript
// test/webapp/scanner/sqli.test.js
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { testSqli } from '../../../src/main/webapp/scanner/sqli.js';

// Mock sendProbe — no real network calls
vi.mock('../../../src/main/webapp/scanner/probe.js', () => ({
  sendProbe: vi.fn(),
}));

import { sendProbe } from '../../../src/main/webapp/scanner/probe.js';
```

### Key Test Cases Per Module

**proxyServer.test.js:**
- CA cert is generated and cached (not regenerated on second call).
- CONNECT tunnel correctly intercepts a mock TLS connection.
- Intercepted request is held until `forwardInterceptedRequest` is called.
- `stopProxy()` closes all open sockets.
- URL with `file://` scheme is rejected.

**sqli.test.js:**
- Time-based detection fires when `sendProbe` resolves after > 4.5s.
- Error-based detection fires when response body contains MySQL error string.
- Boolean-based detection fires when response length differs between true/false payloads.
- Clean request (no injection point) produces no findings.
- Aborted scan emits no findings after abort.

**xss.test.js:**
- Canary reflected unencoded → finding emitted with type `xss-reflected`.
- Canary reflected HTML-encoded → no finding.
- Multiple parameters tested independently.

**intruderEngine.test.js:**
- Sniper mode with 2 positions and 3 payloads fires 6 requests.
- Cluster Bomb with 2 positions of 3 payloads each fires 9 requests.
- Concurrency limit is respected (semaphore).
- Abort stops mid-run.

**decoder.test.js:**
- Base64 round-trip encode/decode.
- URL encode special chars.
- JWT decode extracts header and payload JSON.
- Chain: Base64 → URL encode produces correct output.

**comparer.test.js:**
- Myers diff correctly identifies added and removed lines.
- Identical inputs produce zero diff.
- Large inputs (50kb) complete without hanging.

---

## 14. CSS & Theming

All new UI elements follow the existing glassmorphic dark theme in `src/renderer/style.css`.

### New CSS Variables

```css
:root {
  /* Web App workspace accent — deep purple / violet */
  --webapp-btn:         #8b5cf6;   /* primary accent */
  --webapp-btn-hover:   #7c3aed;
  --webapp-panel-bg:    rgba(30, 20, 50, 0.85);

  /* Severity colors (scanner findings) */
  --severity-critical:  #ef4444;
  --severity-high:      #f97316;
  --severity-medium:    #eab308;
  --severity-low:       #3b82f6;
  --severity-info:      #6b7280;

  /* Proxy intercept indicator */
  --intercept-active:   #ef4444;
  --intercept-pulse:    rgba(239, 68, 68, 0.4);

  /* HTTP method badges */
  --method-get:         #22c55e;
  --method-post:        #3b82f6;
  --method-put:         #f97316;
  --method-delete:      #ef4444;
  --method-patch:       #a855f7;
}
```

### Component Patterns

- **Finding cards:** same card structure as `cloudenum-finding-card` — `border-left: 4px solid var(--severity-<level>)`.
- **Workspace tab bar:** matches the existing pentest header button bar style — `glass` background, `border-bottom: 2px solid var(--webapp-btn)` on active tab.
- **Intercept active indicator:** pulsing red ring around the proxy section header, CSS keyframe animation (same pattern as `#revshell-panel` connection indicator).
- **Virtual scroll table:** `overflow-y: scroll` container with fixed height; rows are absolutely positioned based on scroll offset. Row height: `32px`.
- **Sidebar nav:** `width: 48px` collapsed, `160px` expanded. Transition `width 0.2s ease`. Each item: icon (SVG inline) + label.
- **Code/raw editors:** `font-family: 'Fira Code', 'Courier New', monospace; font-size: 12px; tab-size: 2;`

---

## 15. Consent & Ethics Gate

The consent and authorization gate for Feature 7 is more stringent than the existing pentest consent (which is a one-time checkbox). Web application scanning carries higher risk of unintended harm because it sends active payloads (SQLi, XSS, etc.) to application backends.

### Consent Modal Design

**Trigger:** First time the user attempts to start the Active Scanner (7C) or Intruder (7D.2) with any active payloads.

**Content:**
> "Web Application Active Scanning
>
> You are about to send automated attack payloads to a web application. This includes SQL injection, XSS, command injection, and other techniques that may:
> - Crash the target application
> - Corrupt or delete data in backend databases
> - Trigger security alerts on the target network
> - Violate computer fraud laws if used without authorization
>
> By proceeding, you confirm:
> ✓ I own the target application or have explicit written authorization to test it.
> ✓ I understand this tool is for legitimate security testing only.
> ✓ I accept full legal responsibility for my use of this feature.
>
> Type `AUTHORIZED` to continue: [input field]"

The user must type `AUTHORIZED` exactly. This is stored per-session only — it is NOT persisted to electron-store. The user must re-authorize on each app launch. This is intentional friction.

**Scope confirmation:** After typing `AUTHORIZED`, a second step shows the current target scope and asks: "Confirm that all targets listed below are within your authorized scope: [scope list]". If the scope is empty, the user must define at least one scope entry before scanning can start.

---

## 16. Implementation Sequence

### Milestone 1 — Proxy Foundation (7A)
1. Add `better-sqlite3` as a dependency.
2. Implement `requestStore.js` with SQLite schema + CRUD.
3. Implement CA generation in `proxyServer.js` (no-dep crypto path first; `node-forge` as fallback).
4. Implement HTTP-only proxy (no TLS yet) + history logging.
5. Add IPC handlers in `webappIpc.js`.
6. Build proxy renderer module: history table (non-virtualized first), basic inspector.
7. Add workspace switcher to `index.html` and `index.js`.
8. Write `proxyServer.test.js` and `requestStore.test.js`.

### Milestone 2 — TLS Interception + Intercept Mode
1. Add CONNECT tunnel handling + dynamic cert generation.
2. Add intercept mode (pause/forward/drop).
3. Add WebSocket frame capture.
4. Update renderer: intercept panel, WS history tab.
5. Add CA install IPC handler (platform-specific `certutil` spawn).
6. Update tests.

### Milestone 3 — Repeater (7D.1)
1. Implement `repeaterEngine.js` in main.
2. Build `repeater.js` renderer: editor, response view, history nav, tabs.
3. Wire "Send to Repeater" in HTTP History context menu.
4. Tests.

### Milestone 4 — Crawler + Sitemap (7B)
1. Implement passive `crawler.js` (observe requests from proxy).
2. Build `sitemap.js` renderer: tree view, context menu.
3. Implement `activeCrawler.js` (Playwright integration, graceful fallback).
4. Implement `apiDetector.js` (OpenAPI + GraphQL probes).
5. Tests.

### Milestone 5 — Scanner Core (7C)
1. Implement `scanner/probe.js` (shared HTTP helper).
2. Implement `scanner/headers.js` and `scanner/cors.js` (passive, lower risk, good for validating the pipeline).
3. Implement `scanner/sqli.js`, `scanner/xss.js`, `scanner/pathTraversal.js`.
4. Implement `scanner/ssrf.js`, `scanner/xxe.js`, `scanner/cmdInjection.js`.
5. Implement `scanner/brokenAuth.js`, `scanner/deserialize.js`.
6. Implement `scanner/index.js` orchestrator with queue + concurrency.
7. Build `scanner.js` renderer: config panel, findings table, export.
8. Add consent gate.
9. Tests for all scanner modules.

### Milestone 6 — Intruder + Sequencer (7D.2, 7D.3)
1. Implement `intruderEngine.js`.
2. Build `intruder.js` renderer: position marker UI, payload config, results table.
3. Implement `sequencerEngine.js` (token collection + FIPS entropy tests).
4. Build `sequencer.js` renderer: capture UI, entropy charts (Canvas-based, no chart library).
5. Tests.

### Milestone 7 — Decoder + Comparer (7D.4, 7D.5)
1. Build `decoder.js` renderer (pure renderer, no IPC for most transforms; add `DECODER_TRANSFORM` for gzip/hash).
2. Build `comparer.js` renderer (Myers diff, pure JS).
3. Tests.

### Milestone 8 — OAST + DOM Invader + GraphQL (7E)
1. Implement `oastServer.js` (HTTP callback; DNS callback with privilege fallback).
2. Write `domInvaderAgent.js` (injected script).
3. Integrate OAST URL injection into scanner modules (ssrf.js, xxe.js, sqli.js, cmdInjection.js).
4. Implement DOM Invader injection in `proxyServer.js`.
5. Extend `apiDetector.js` with GraphQL active tests.
6. Tests.

### Milestone 9 — Polish + Integration
1. Network workspace pivot: "Open in Web App" button on host cards.
2. Web vuln badge on host cards in network workspace.
3. Unified findings export (JSON + HTML report).
4. Settings modal additions: proxy port, proxy scope, wordlist paths, scanner concurrency.
5. Update `README.md` and `getting-started-guide.md` with Web App workspace documentation.
6. Full integration test pass (manual).

---

## 17. Dependency Analysis

### New npm Dependencies

| Package | Version | Used For | Rationale |
|---|---|---|---|
| `better-sqlite3` | latest | Request history DB | Synchronous, no native addon issues on Electron; previously recommended in Feature 1 brainstorm |
| `playwright-core` | latest | Active crawler | Soft dep (graceful fallback); user installs separately. Do NOT bundle. |
| `node-html-parser` | latest | Passive spider HTML parsing | Zero-dep, fast, forgiving parser; no `jsdom` overhead |

### Avoided Dependencies (intentional)

| Package | Why Avoided |
|---|---|
| `http-mitm-proxy` | Adds ~15 transitive deps; implementing CONNECT tunnel in Node's `net` is ~150 lines and gives full control |
| `node-forge` | Only needed if `crypto.generateKeyPairSync` X.509 builder proves too complex; use as fallback, not primary |
| `axios` / `node-fetch` | Scanner uses same `http`/`https` pattern as `dirFuzzer.js` — zero new deps |
| `sqlmap` (binary) | Would be an external dependency; internal SQLi detection is sufficient for detection (not exploitation) |
| `jsdom` | Too heavy for sitemap parsing; `node-html-parser` is sufficient |
| `d3` / `chart.js` | Sequencer charts done with Canvas API directly; no charting library needed |
| `diff` (npm) | Myers diff implemented in ~80 lines of pure JS; Comparer has no external dep |

### Existing Dependencies Leveraged

- `electron` — `BrowserWindow`, `contextBridge`, `ipcMain`, `ipcRenderer`, `net`, `shell`
- Node built-ins: `http`, `https`, `net`, `dgram`, `crypto`, `fs`, `url`, `worker_threads`
- Existing patterns: `createSemaphore()` (from `cloudEnum.js`), `httpGet()` (from `cloudEnum.js`), `SAFE_PATH_RE` (from `dirFuzzer.js`)

---

*End of Feature 7 Implementation Plan*
