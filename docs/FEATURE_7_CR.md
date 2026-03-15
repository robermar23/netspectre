Please address the comments from this code review:

## Overall Comments
- The URL and raw HTTP request construction logic (e.g., in proxy history context actions, sitemap `_handleContextAction`, and `_sendToRepeater` in scanner.js) is duplicated in several places; consider extracting a shared helper to keep behavior consistent and avoid subtle divergence over time.
- In `SEQUENCER_COLLECT`, the requested `count` is only upper-bounded; it may be worth normalizing it to a positive integer (e.g., clamp to `[1, 1000]`) before passing it into `collectTokens` to avoid unexpected behavior on negative or non-numeric inputs.

## Individual Comments

### Comment 1
<location path="src/main/webapp/ipc/webappIpc.js" line_range="486-488" />
<code_context>
+    try { new URL(opts.targetUrl); } catch {
+      return { success: false, error: `Invalid targetUrl: ${opts.targetUrl}` };
+    }
+    // Hard cap on total payload count (sum across all lists)
+    const totalPayloads = (opts.payloadLists ?? [[]]).reduce((s, l) => s + (l?.length ?? 0), 0);
+    if (totalPayloads > 1_000_000) {
+      return { success: false, error: 'Payload count exceeds maximum (1,000,000).' };
+    }
</code_context>
<issue_to_address>
**issue (bug_risk):** Payload cap checks only list lengths, not the effective number of requests for multi-list attack types.

The cap on `totalPayloads` only limits the number of configured payload items, not the actual number of generated requests for modes that combine lists (e.g., pitchfork/cluster-bomb). If those modes are supported, you can still exceed 1,000,000 requests. Consider instead capping based on the computed request count for the selected attack type, or enforcing a hard limit inside the intruder engine once the final cardinality is known, to avoid "attack explosion" from large combinations.
</issue_to_address>

### Comment 2
<location path="src/main/webapp/ipc/webappIpc.js" line_range="541-470" />
<code_context>
+  ipcMain.handle(IPC_CHANNELS.DECODER_TRANSFORM, async (_event, { transform, input } = {}) => {
</code_context>
<issue_to_address>
**🚨 issue (security):** Decoder IPC handler lacks basic input-size limits, which could allow very large payloads or gzip bombs.

The handler currently forwards unbounded renderer `input` directly into `zlib`/`crypto`. This makes the main process vulnerable to gzip bombs or very large payloads consuming excessive CPU/memory. Please enforce a reasonable maximum input size (e.g., a few MB, and a stricter limit for gzip after base64 decoding) and fail fast with a clear error when the limit is exceeded, rather than relying on `zlib` to error out under load.
</issue_to_address>

### Comment 3
<location path="src/renderer/modules/webapp/proxy.js" line_range="416-418" />
<code_context>
     } else if (action === 'probe-network') {
       const row = allRows.find(r => r.id === selectedRowId);
       if (row?.host) _probeHostInNetwork(row.host);
+    } else if (action === 'repeater') {
+      const row = allRows.find(r => r.id === selectedRowId);
+      if (row) {
+        const raw   = _buildRawText(row);
+        const url   = `${row.protocol || 'http'}://${row.host}${row.path ?? '/'}${row.query ? '?' + row.query : ''}`;
</code_context>
<issue_to_address>
**suggestion:** Repeated URL construction logic across multiple context-menu actions could be centralized.

The `repeater`, `intruder`, `scanner`, and `sitemap` branches currently rebuild the URL with identical logic:
```js
const url = `${row.protocol || 'http'}://${row.host}${row.path ?? '/'}${row.query ? '?' + row.query : ''}`;
```
Extract this into a shared helper (e.g. `_rowToUrl(row)`) and call it from each action so any future changes to URL construction (IPv6, ports, query encoding, etc.) are applied consistently in one place.

Suggested implementation:

```javascript
  _wireConsentModal();
  _wireProxyControls();
  _wireSubtabs();

  const _rowToUrl = (row) =>
    `${row.protocol || 'http'}://${row.host}${row.path ?? '/'}${row.query ? '?' + row.query : ''}`;

```

```javascript
    } else if (action === 'repeater') {
      const row = allRows.find(r => r.id === selectedRowId);
      if (row) {
        const raw   = _buildRawText(row);
        const url   = _rowToUrl(row);
        const label = `${row.method} ${row.path ?? '/'}`;
        document.dispatchEvent(new CustomEvent('repeater:sendTo', { detail: { raw, url, label } }));
      }
    } else if (action === 'intruder') {
      const row = allRows.find(r => r.id === selectedRowId);
      if (row) {
        const raw = _buildRawText(row);
        const url = _rowToUrl(row);
        document.dispatchEvent(new CustomEvent('intruder:sendTo', { detail: { raw, url } }));
      }

```

The same `_rowToUrl(row)` helper should also be used in the `scanner` and `sitemap` context-menu branches, replacing any occurrences of:
```js
const url = `${row.protocol || 'http'}://${row.host}${row.path ?? '/'}${row.query ? '?' + row.query : ''}`;
```
with:
```js
const url = _rowToUrl(row);
```
Make these replacements wherever those actions are handled in this file to fully centralize URL construction.
</issue_to_address>

### Comment 4
<location path="src/main/webapp/ipc/webappIpc.js" line_range="461" />
<code_context>
+
+  // ─── Feature 7D — Repeater ────────────────────────────────────────────────────
+
+  ipcMain.handle(IPC_CHANNELS.REPEATER_SEND, async (_event, opts = {}) => {
+    if (!opts.url) return { success: false, error: 'url is required' };
+    try { new URL(opts.url); } catch {
</code_context>
<issue_to_address>
**issue (complexity):** Consider extracting shared helpers for URL validation, decoder transforms, and repeater cancellation to keep IPC handlers small and focused on orchestration logic.

You can trim some incidental complexity here by extracting a few small helpers while preserving all behavior.

### 1) Repeated URL validation

`REPEATER_SEND`, `INTRUDER_START`, and `SEQUENCER_COLLECT` hand-roll nearly identical URL checks. A small shared helper keeps handlers focused on orchestration:

```js
// near the bottom of the file (helpers section)
function _validateUrlField(opts, field, label = field) {
  const value = opts?.[field];
  if (!value) {
    return { ok: false, error: `${label} is required` };
  }
  try {
    new URL(value);
  } catch {
    return { ok: false, error: `Invalid ${label}: ${value}` };
  }
  return { ok: true, value };
}
```

Then the handlers become simpler and consistent:

```js
ipcMain.handle(IPC_CHANNELS.REPEATER_SEND, async (_event, opts = {}) => {
  const { ok, error } = _validateUrlField(opts, 'url');
  if (!ok) return { success: false, error };

  try {
    const result = await sendRepeaterRequest(opts); // see AbortController note below
    return { success: true, ...result };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle(IPC_CHANNELS.INTRUDER_START, async (_event, opts = {}) => {
  if (isIntruderRunning()) {
    return { success: false, error: 'Intruder already running.' };
  }
  if (!opts.rawTemplate) {
    return { success: false, error: 'rawTemplate is required' };
  }

  const { ok, error } = _validateUrlField(opts, 'targetUrl', 'targetUrl');
  if (!ok) return { success: false, error };

  // ...unchanged rest of handler...
});

ipcMain.handle(IPC_CHANNELS.SEQUENCER_COLLECT, async (_event, opts = {}) => {
  const { ok, error } = _validateUrlField(opts, 'url');
  if (!ok) return { success: false, error };

  // ...unchanged rest of handler...
});
```

### 2) Decoder transforms: factor gzip + hashing helpers

`DECODER_TRANSFORM` currently mixes IPC, zlib callback-wrapping, and crypto hashing in one switch. Pulling the low-level bits out makes the handler shorter and easier to scan:

```js
// helpers near bottom

const gzip = (buf) =>
  new Promise((res, rej) => {
    zlib.gzip(buf, (err, out) => (err ? rej(err) : res(out)));
  });

const gunzip = (buf) =>
  new Promise((res, rej) => {
    zlib.gunzip(buf, (err, out) => (err ? rej(err) : res(out)));
  });

async function _gzipCompressToBase64(inputUtf8) {
  const buf = Buffer.from(inputUtf8, 'utf8');
  const compressed = await gzip(buf);
  return compressed.toString('base64');
}

async function _gzipDecompressFromBase64(inputBase64) {
  const buf = Buffer.from(inputBase64, 'base64');
  const decompressed = await gunzip(buf);
  return decompressed.toString('utf8');
}

function _hash(transform, input) {
  return crypto.createHash(transform).update(input).digest('hex');
}
```

Then the handler becomes mostly a mapping from `transform` → helper:

```js
ipcMain.handle(
  IPC_CHANNELS.DECODER_TRANSFORM,
  async (_event, { transform, input } = {}) => {
    if (typeof input !== 'string') {
      return { success: false, error: 'input must be a string' };
    }

    try {
      let output;
      switch (transform) {
        case 'gzip-compress':
          output = await _gzipCompressToBase64(input);
          break;
        case 'gzip-decompress':
          output = await _gzipDecompressFromBase64(input);
          break;
        case 'md5':
        case 'sha1':
        case 'sha256':
        case 'sha512':
          output = _hash(transform, input);
          break;
        default:
          return {
            success: false,
            error: `Unknown server-side transform: ${transform}`,
          };
      }
      return { success: true, output };
    } catch (err) {
      return { success: false, error: err.message };
    }
  },
);
```

This keeps IPC concerns at the top level and the transform implementations in focused helpers.

### 3) AbortController in `REPEATER_SEND`

`REPEATER_SEND` creates an `AbortController` but doesn’t expose cancellation to the caller or share this pattern elsewhere. Either:

- Make cancellation a first-class IPC pattern (e.g. `REPEATER_SEND_CANCEL` with stored controllers), or
- Hide the controller inside the repeater engine so the handler doesn’t have to worry about it.

If you don’t need per-call abort control at the IPC layer yet, you can move it into `sendRepeaterRequest`:

```js
// repeaterEngine.js
export async function sendRepeaterRequest(opts) {
  const ctrl = new AbortController();
  return _sendRepeaterRequestWithSignal(opts, ctrl.signal);
}
```

and keep the handler minimal:

```js
ipcMain.handle(IPC_CHANNELS.REPEATER_SEND, async (_event, opts = {}) => {
  const { ok, error } = _validateUrlField(opts, 'url');
  if (!ok) return { success: false, error };

  try {
    const result = await sendRepeaterRequest(opts);
    return { success: true, ...result };
  } catch (err) {
    return { success: false, error: err.message };
  }
});
```

This preserves all behavior while making `registerIpcHandlers` shorter and more coherent.
</issue_to_address>

### Comment 5
<location path="src/renderer/modules/webapp/sitemap.js" line_range="707" />
<code_context>
     case 'open-browser':
       window.electronAPI.openUrl(url);
       break;
+    case 'send-repeater': {
+      const parsed    = (() => { try { return new URL(url); } catch { return null; } })();
+      const pathQuery = parsed ? (parsed.pathname + parsed.search) : '/';
</code_context>
<issue_to_address>
**issue (complexity):** Consider extracting the shared GET-request-building logic and routing all detail buttons through `_handleContextAction` to remove duplication and keep the actions wired in a uniform way.

You can reduce the added complexity in `_handleContextAction` and make the detail actions more uniform with two small refactors.

### 1. Extract shared GET request builder

The `send-repeater` and `send-intruder` cases are now almost identical. Pull the URL parsing + request construction into a helper so the switch reads more clearly and you only have one place to maintain the logic.

```js
// near _handleContextAction

function safeParseUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function buildSimpleGetRequest(url) {
  const parsed    = safeParseUrl(url);
  const pathQuery = parsed ? (parsed.pathname + parsed.search) : '/';
  const host      = parsed ? parsed.host : url;
  const raw       = `GET ${pathQuery} HTTP/1.1\r\nHost: ${host}\r\n\r\n`;
  return { raw, pathQuery, host };
}
```

Then simplify the switch:

```js
function _handleContextAction(action, url) {
  if (!url) return;

  switch (action) {
    case 'open-browser':
      window.electronAPI.openUrl(url);
      break;

    case 'send-repeater': {
      const { raw, pathQuery } = buildSimpleGetRequest(url);
      document.dispatchEvent(new CustomEvent('repeater:sendTo', {
        detail: { raw, url, label: `GET ${pathQuery}` },
      }));
      break;
    }

    case 'send-intruder': {
      const { raw } = buildSimpleGetRequest(url);
      document.dispatchEvent(new CustomEvent('intruder:sendTo', {
        detail: { raw, url },
      }));
      break;
    }

    // ... other cases unchanged
  }
}
```

This keeps behavior identical (same fallback when `new URL(url)` throws) but removes duplication and the inline IIFE.

### 2. Use `_detailAction` consistently for detail buttons

You already introduced `_detailAction` for several buttons. You can wire the remaining two through `_handleContextAction` as well, which keeps all detail actions going through the same path and leverages the existing `api-detect` / `probe-network` cases.

```js
// Detail Action Buttons
const _detailAction = (action) => () => {
  if (_selectedNode) _handleContextAction(action, _selectedNode.url);
};

document.getElementById('btn-sitemap-send-repeater') ?.addEventListener('click', _detailAction('send-repeater'));
document.getElementById('btn-sitemap-send-intruder') ?.addEventListener('click', _detailAction('send-intruder'));
document.getElementById('btn-sitemap-send-dirfuzzer')?.addEventListener('click', _detailAction('send-dirfuzzer'));
document.getElementById('btn-sitemap-open-browser')  ?.addEventListener('click', _detailAction('open-browser'));
document.getElementById('btn-sitemap-probe-network') ?.addEventListener('click', _detailAction('probe-network'));
document.getElementById('btn-sitemap-api-detect-url')?.addEventListener('click', _detailAction('api-detect'));
```

This removes the two remaining inline handlers, keeps all functionality, and makes the detail action wiring uniform and easier to extend.
</issue_to_address>