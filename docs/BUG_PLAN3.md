# BUG_PLAN3 — Implementation Plan for Remaining Open Bugs

> Branch: `fix-missing` | Date: 2026-03-16
> Covers: Lines 50–52 of `docs/BUGS.md` (the three remaining `- [ ]` items)

---

## Table of Contents

1. [Bug Overview](#bug-overview)
2. [BUG-50 — Web Vulnerability Badge Missing on Host Cards & Host Details](#bug-50)
3. [BUG-51 — Brute-Force Feature Must Be a Resizable Panel, Not a Modal](#bug-51)
4. [BUG-52 — Activity Log for Web Workspace SiteMap & DirFuzz Panels](#bug-52)
5. [Cross-Cutting Concerns](#cross-cutting-concerns)
6. [Test Coverage Plan](#test-coverage-plan)
7. [Implementation Order & Dependencies](#implementation-order--dependencies)

---

## Bug Overview

| ID | Description | Severity | Effort |
|----|-------------|----------|--------|
| BUG-50 | Web vuln badge never appears on host card; no count; no persistence; no host details section | High | Medium |
| BUG-51 | Brute-force opens as a blocking modal; must become a resizable side-panel | Medium | Medium |
| BUG-52 | SiteMap and DirFuzz panels lack the activity-log UI the scanner has | Low–Medium | Medium |

---

## BUG-50

### Web Vulnerability Badge Missing on Host Cards & Host Details

#### Root Cause Analysis

`_updateNetworkBadge(finding)` in `src/renderer/modules/webapp/scanner.js` (lines 469–503):

1. **No count** — badge text is hardcoded `'⚠ Web Vulns'` with no count. Once injected it is never updated, so subsequent findings add no visible change.
2. **Badge never re-applied after re-render** — `getSecurityBadgeData()` in `scanControls.js` (lines 252–304) is the function that determines the host card security posture badge. It does **not** consult `host.hasWebVulns` or any web-finding count. When the host list re-renders the web-vuln badge injected ad-hoc is wiped.
3. **No `reapplyBadges` hook** — `initScanControls` in `index.js` (line 73) passes `cloudEnum.reapplyBadges` as `onHostsRendered`. The scanner module exports no equivalent function. After any re-render, web-vuln badges are lost.
4. **Host object never updated with finding metadata** — `host.hasWebVulns = true` is set on the in-memory host but no structured `host.webVulnFindings` array or `host.webVulnCount` number is persisted. `saveResults(state.hosts)` in `scanControls.js` (line 840) serialises the hosts array as-is; any property added ad-hoc will survive that call, but the findings detail is lost across sessions.
5. **No web-vuln section in Host Details panel** — `hostDetails.js` renders cloud findings via `renderCloudFindingsSection()` but has no parallel `renderWebVulnSection()`. The host details panel shows no web vulnerability data.
6. **Domain → IP matching** — the DNS resolution path exists but if DNS fails and the scan target was an IP, `hostname` may equal the IP string. The guard `h.ip === hostname` handles this, but `h.hostname === hostname` only works if the hostname is already known to the scanner.

#### Affected Files

| File | Lines | Change |
|------|-------|--------|
| `src/renderer/modules/webapp/scanner.js` | 469–503, ~24, ~46 | Badge update with count; `host.webVulnFindings[]`; export `reapplyWebVulnBadges` |
| `src/renderer/modules/scanControls.js` | 252–304, 839–842 | `getSecurityBadgeData` reads `host.webVulnCount`; save includes findings metadata |
| `src/renderer/modules/hostDetails.js` | after cloud findings section | New `renderWebVulnSection(host)` |
| `src/renderer/index.js` | 73 | Pass `scanner.reapplyWebVulnBadges` as `onHostsRendered` (chain with existing) |
| `src/renderer/index.html` | host-details panel | Add `#host-webvuln-section` container |
| `src/renderer/webapp.css` | — | `.web-vuln-badge` count style; `.webvuln-row` detail row |
| `src/main/ipc/fileIpc.js` | save handler | Strip large `webVulnFindings` payloads if needed (truncate to last 200) |

#### Detailed Implementation Steps

##### Step 1 — Structured storage on the host object

In `scanner.js`, replace the ad-hoc `match.hasWebVulns = true` pattern:

```js
// At top of module
const WEB_VULN_MAX_STORE = 200; // per host, cap stored findings

function _attachFindingToHost(host, finding) {
  if (!Array.isArray(host.webVulnFindings)) host.webVulnFindings = [];
  host.webVulnFindings.push({
    severity:    finding.severity,
    type:        finding.type,
    url:         finding.url,
    title:       finding.title,
    description: finding.description,
    remediation: finding.remediation,
    timestamp:   Date.now(),
  });
  if (host.webVulnFindings.length > WEB_VULN_MAX_STORE)
    host.webVulnFindings.shift();
  host.webVulnCount = host.webVulnFindings.length;
  host.hasWebVulns  = true;
}
```

Call `_attachFindingToHost(match, finding)` inside `_updateNetworkBadge`.

##### Step 2 — Badge with live count

Replace the single-injection guard:

```js
// Remove: if (card && !card.querySelector('.web-vuln-badge')) { ... }
// Replace with:
function _refreshWebVulnBadge(card, host) {
  let badge = card.querySelector('.web-vuln-badge');
  if (!badge) {
    badge = document.createElement('span');
    badge.className = 'web-vuln-badge';
    badge.title = 'Web vulnerabilities found by active scanner — click for details';
    card.querySelector('.host-meta')?.appendChild(badge);
  }
  const count = host.webVulnCount ?? 0;
  badge.textContent = `⚠ ${count} Web Vuln${count !== 1 ? 's' : ''}`;
}
```

Call `_refreshWebVulnBadge(card, match)` after `_attachFindingToHost`.

##### Step 3 — Export `reapplyWebVulnBadges`

Add a named export to `scanner.js`:

```js
export function reapplyWebVulnBadges() {
  if (!state?.hosts) return;
  for (const host of state.hosts) {
    if (!host.hasWebVulns) continue;
    const card = document.querySelector(`.host-card[data-ip="${host.ip}"]`);
    if (card) _refreshWebVulnBadge(card, host);
  }
}
```

##### Step 4 — Wire into `initScanControls`

In `src/renderer/index.js`:

```js
// line ~73 — chain both badge re-apply callbacks
initScanControls({
  openDetailsPanel: hostDetails.openPanel,
  onHostsRendered: (renderedHosts) => {
    cloudEnum.reapplyBadges(renderedHosts);
    scanner.reapplyWebVulnBadges();           // ← add this
  },
});
```

Import `reapplyWebVulnBadges` from the scanner module at the top of `index.js`.

##### Step 5 — `getSecurityBadgeData` integration

In `scanControls.js`, extend `getSecurityBadgeData(host)`:

```js
// Add BEFORE the existing posture logic (insert as highest-priority tier):
if (host.hasWebVulns && host.webVulnCount > 0) {
  const critCount = (host.webVulnFindings ?? [])
    .filter(f => f.severity === 'critical' || f.severity === 'high').length;
  if (critCount > 0) {
    return {
      posture: `⚠ ${critCount} Web Crit`,
      badgeClass: 'danger',
      icon: '🌐',
    };
  }
  return {
    posture: `⚠ ${host.webVulnCount} Web Vuln${host.webVulnCount !== 1 ? 's' : ''}`,
    badgeClass: 'warning',
    icon: '🌐',
  };
}
```

Insert this check between the existing Monitor/Deep-audit checks and the Port risk check so that web findings surface appropriately in the security posture hierarchy.

##### Step 6 — Host Details panel web-vuln section

In `src/renderer/index.html`, inside the host-details panel, add a collapsible container after the cloud findings section:

```html
<!-- Web Vulnerability Findings (populated by scanner.js) -->
<div id="host-webvuln-section" class="host-detail-section" style="display:none;">
  <div class="section-header">
    <h3 class="section-title">🌐 Web Vulnerabilities</h3>
    <span id="host-webvuln-count" class="badge badge-warning"></span>
    <button id="host-webvuln-goto-scanner" class="btn secondary xs"
            title="Open in Web Scanner">Open Scanner ↗</button>
  </div>
  <div id="host-webvuln-list" class="webvuln-list"></div>
</div>
```

In `src/renderer/modules/hostDetails.js`, add `renderWebVulnSection(host)`:

```js
function renderWebVulnSection(host) {
  const section = document.getElementById('host-webvuln-section');
  const list    = document.getElementById('host-webvuln-list');
  const count   = document.getElementById('host-webvuln-count');
  const gotoBtn = document.getElementById('host-webvuln-goto-scanner');
  if (!section || !list) return;

  const findings = host.webVulnFindings ?? [];
  if (findings.length === 0) {
    section.style.display = 'none';
    return;
  }
  section.style.display = 'block';
  count.textContent = `${findings.length} finding${findings.length !== 1 ? 's' : ''}`;
  list.innerHTML = '';

  // Sort: critical → high → medium → low → info
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) =>
    (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

  for (const f of sorted) {
    const row = document.createElement('div');
    row.className = `webvuln-row sev-${f.severity ?? 'info'}`;
    row.innerHTML = `
      <span class="webvuln-sev-badge sev-${f.severity}">${f.severity?.toUpperCase() ?? 'INFO'}</span>
      <span class="webvuln-type">${_esc(f.type ?? '')}</span>
      <span class="webvuln-url" title="${_esc(f.url ?? '')}">${_truncUrl(f.url, 50)}</span>
      <details class="webvuln-detail">
        <summary>Details</summary>
        <p><strong>Description:</strong> ${_esc(f.description ?? '')}</p>
        <p><strong>Remediation:</strong> ${_esc(f.remediation ?? '')}</p>
      </details>`;
    list.appendChild(row);
  }

  // Open Scanner pivot
  if (gotoBtn) {
    gotoBtn.onclick = () => {
      const url = findings[0]?.url ?? '';
      window.__openScannerPanel?.(url);
    };
  }
}

function _esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _truncUrl(url, max) {
  if (!url) return '';
  return url.length > max ? url.slice(0, max) + '…' : url;
}
```

Call `renderWebVulnSection(host)` from inside the main host-details render function (wherever cloud findings are rendered).

##### Step 7 — CSS additions in `webapp.css`

```css
/* Web-vuln badge on host cards */
.web-vuln-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 10px;
  background: rgba(231, 76, 60, 0.15);
  border: 1px solid rgba(231, 76, 60, 0.45);
  color: #e74c3c;
  cursor: default;
  white-space: nowrap;
}

/* Host details web-vuln section */
.webvuln-list { display: flex; flex-direction: column; gap: 6px; margin-top: 8px; }
.webvuln-row {
  display: grid;
  grid-template-columns: 70px 120px 1fr;
  align-items: start;
  gap: 8px;
  padding: 6px 10px;
  border-radius: 6px;
  background: rgba(0,0,0,0.25);
  border-left: 3px solid var(--border-glass);
  font-size: 12px;
}
.webvuln-row.sev-critical { border-left-color: #e74c3c; }
.webvuln-row.sev-high     { border-left-color: #e67e22; }
.webvuln-row.sev-medium   { border-left-color: #f1c40f; }
.webvuln-row.sev-low      { border-left-color: #3498db; }
.webvuln-row.sev-info     { border-left-color: #95a5a6; }
.webvuln-sev-badge {
  font-size: 9px; font-weight: 700; padding: 1px 5px;
  border-radius: 3px; text-align: center;
  background: rgba(0,0,0,0.4); text-transform: uppercase;
}
.sev-critical { color: #e74c3c; }
.sev-high     { color: #e67e22; }
.sev-medium   { color: #f1c40f; }
.sev-low      { color: #3498db; }
.sev-info     { color: #95a5a6; }
.webvuln-url  { color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.webvuln-detail { grid-column: 1 / -1; font-size: 11px; color: var(--text-muted); }
.webvuln-detail summary { cursor: pointer; color: var(--accent); }
```

##### Step 8 — Session persistence

`state.hosts` is already serialised by `api.saveResults(state.hosts)`. Because `host.webVulnFindings[]` and `host.webVulnCount` are now plain data properties on each host object, they will persist automatically.

On session **load**, add a re-apply pass in the existing session-load handler (wherever hosts are repopulated from a loaded JSON file):

```js
// After hosts are loaded from disk and re-rendered:
scanner.reapplyWebVulnBadges();
```

To guard against very large sessions, cap the stored array in `fileIpc.js` save handler:

```js
// In the save handler, before JSON.stringify:
const sanitised = hosts.map(h => ({
  ...h,
  webVulnFindings: (h.webVulnFindings ?? []).slice(-200),
}));
```

---

## BUG-51

### Brute-Force Feature Must Be a Resizable Panel, Not a Modal

#### Root Cause Analysis

`src/renderer/modules/bruteForce.js` controls `#bruteforce-modal-overlay` — a centred, full-screen blocking modal. Every other offensive feature (Dir Fuzzer, Share Enumerator, Cred Spray, Rev Shell Listener) uses an `<aside class="details-panel glass-panel">` with a draggable `<div class="resizer">` strip. The brute-force module was the only one never migrated.

#### Affected Files

| File | Change |
|------|--------|
| `src/renderer/index.html` | Remove `#bruteforce-modal-overlay`; add `#bruteforce-panel` + `#bruteforce-resizer` |
| `src/renderer/modules/bruteForce.js` | Replace modal show/hide with `openPanelHelper` / `closePanelHelper` pattern |
| `src/renderer/style.css` | Remove `.bf-modal` sizing rules; ensure panel width rule |

#### Detailed Implementation Steps

##### Step 1 — Replace markup in `index.html`

**Remove** the entire `<div id="bruteforce-modal-overlay" class="modal-overlay hidden">` block (lines 2599–2717).

**Add** a resizer + panel pair in the same location as the other pentest panels (after `#credspray-resizer` / `#credspray-panel`, before `</div>` closing the panels wrapper):

```html
<div id="bruteforce-resizer" class="resizer" style="display: none;"></div>
<aside id="bruteforce-panel" class="details-panel glass-panel" style="width: 580px; display: none;">
  <div class="panel-header" style="border-bottom-color: rgba(231, 76, 60, 0.3);">
    <h2><span class="icon">⚔️</span> Brute-Force Attack</h2>
    <button id="btn-close-bruteforce-panel" class="btn icon-only" title="Close Panel">✕</button>
  </div>

  <div class="panel-body" style="padding: 20px; display: flex; flex-direction: column; gap: 16px; overflow-y: auto; flex: 1;">

    <!-- Target Info -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
      <div class="form-group">
        <label class="form-label">Target IP</label>
        <input type="text" id="bf-target-ip" class="text-input full-width"
               placeholder="e.g. 192.168.1.10" readonly>
      </div>
      <div class="form-group">
        <label class="form-label">Port</label>
        <input type="number" id="bf-port" class="text-input full-width"
               value="22" min="1" max="65535">
      </div>
    </div>

    <!-- Protocol -->
    <div class="form-group">
      <label class="form-label">Protocol</label>
      <select id="bf-protocol" class="dropdown-select full-width">
        <option value="ssh">SSH (22)</option>
        <option value="ftp">FTP (21)</option>
        <option value="smb">SMB (445)</option>
        <option value="smb2">SMB2 (445)</option>
        <option value="rdp">RDP (3389)</option>
        <option value="http-get">HTTP GET (80)</option>
        <option value="http-post">HTTP POST (80)</option>
        <option value="telnet">Telnet (23)</option>
        <option value="mysql">MySQL (3306)</option>
        <option value="mssql">MSSQL (1433)</option>
        <option value="postgres">PostgreSQL (5432)</option>
        <option value="vnc">VNC (5900)</option>
      </select>
    </div>

    <!-- Credentials -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
      <div class="form-group">
        <label class="form-label">Username
          <span style="font-size: 10px; color: var(--text-muted);">(single login name)</span>
        </label>
        <input type="text" id="bf-username" class="text-input full-width" placeholder="e.g. admin">
      </div>
      <div class="form-group">
        <label class="form-label">Password Wordlist
          <span style="font-size: 10px; color: var(--text-muted);">(one per line)</span>
        </label>
        <div style="display: flex; gap: 6px;">
          <input type="text" id="bf-wordlist-path" class="text-input" style="flex: 1;"
                 placeholder="Select .txt file…" readonly>
          <button id="btn-bf-browse-wordlist" class="btn secondary icon-only"
                  title="Browse for password wordlist file">📂</button>
        </div>
      </div>
    </div>

    <!-- Advanced Options -->
    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px;">
      <div class="form-group">
        <label class="form-label">
          Threads <span id="bf-threads-val" style="color: var(--pentest);">4</span>
        </label>
        <input type="range" id="bf-threads" min="1" max="16" value="4" class="bf-range-slider">
      </div>
      <div class="form-group">
        <label class="form-label">Delay (ms)</label>
        <input type="number" id="bf-delay" class="text-input full-width"
               value="0" min="0" max="10000">
      </div>
      <div class="form-group">
        <label class="form-label">Max Attempts</label>
        <input type="number" id="bf-max-attempts" class="text-input full-width"
               value="10000" min="1" max="50000">
      </div>
    </div>

    <!-- Controls -->
    <div style="display: flex; gap: 8px;">
      <button id="btn-bf-start" class="btn pentest full-width">
        <span class="icon">⚔️</span> Start Attack
      </button>
      <button id="btn-bf-stop" class="btn danger-outline" style="width: 120px;" disabled>
        <span class="icon">🛑</span> Stop
      </button>
    </div>

    <!-- Progress -->
    <div id="bf-progress-container" style="display: none;">
      <div class="bf-progress-bar">
        <div id="bf-progress-fill" class="bf-progress-fill"></div>
      </div>
      <div id="bf-progress-text"
           style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
        0 attempts
      </div>
    </div>

    <!-- Results Table -->
    <div id="bf-results-container"
         style="max-height: 300px; overflow-y: auto; border: 1px solid var(--border-glass);
                border-radius: 6px; background: rgba(0,0,0,0.3); flex-shrink: 0;">
      <table class="data-table bf-results-table" style="width: 100%; font-size: 11px;">
        <thead style="position: sticky; top: 0; background: #16161c; z-index: 1;">
          <tr>
            <th style="width: 70px;">Time</th>
            <th>Username</th>
            <th>Password</th>
            <th style="width: 60px;">Status</th>
          </tr>
        </thead>
        <tbody id="bf-results-body">
          <tr>
            <td colspan="4"
                style="text-align:center; color: var(--text-muted); padding: 16px;">
              Configure and start an attack above
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Error Display -->
    <div id="bf-error-display"
         style="display: none; color: var(--danger); font-size: 12px; padding: 8px;
                background: rgba(235,94,94,0.1); border-radius: 4px;
                border-left: 3px solid var(--danger);"></div>

  </div>
</aside>
```

##### Step 2 — Update `bruteForce.js`

Replace the modal-centric refs and helpers with the same `openPanelHelper` / `closePanelHelper` pattern used by `credSpray.js`:

```js
// --- top of module, replace const bfOverlay = ... ---
function openPanelHelper(panel, resizer) {
  if (!panel) return;
  panel.style.display = 'flex';
  setTimeout(() => panel.classList.add('open'), 10);
  if (resizer) resizer.style.display = 'block';
}

function closePanelHelper(panel, resizer) {
  if (!panel) return;
  panel.classList.remove('open');
  setTimeout(() => {
    panel.style.display = 'none';
    if (resizer) resizer.style.display = 'none';
  }, 300);
}

const ui = {
  panel:    document.getElementById('bruteforce-panel'),
  resizer:  document.getElementById('bruteforce-resizer'),
  btnClose: document.getElementById('btn-close-bruteforce-panel'),
  btnOpen:  document.getElementById('btn-bruteforce-open'),   // header button (unchanged)
  // ... all other existing element refs remain the same ...
};
```

Replace every `bfOverlay.classList.add('hidden')` / `bfOverlay.classList.remove('hidden')` call with `closePanelHelper(ui.panel, ui.resizer)` / `openPanelHelper(ui.panel, ui.resizer)`.

The `openBruteForceModal(ip, port, protocol)` export should be renamed to `openBruteForcePanel(ip, port, protocol)` and callers updated in `hostDetails.js`.

##### Step 3 — Resizer drag behaviour

The resizer element uses the shared CSS class `resizer` which already receives the mouse-drag width logic via the existing `setupResizer()` utility (or inline drag handlers). Verify the resizer element ID `bruteforce-resizer` is wired up the same way as `dirfuzz-resizer` or `credspray-resizer` — check for a `setupResizer` or equivalent call in the renderer init and add `bruteforce-resizer` → `bruteforce-panel` mapping there.

##### Step 4 — Header button

The header button `#btn-bruteforce-open` already exists and routes through the consent flow. No change required except ensuring it calls `openBruteForcePanel()` instead of the old modal function.

##### Step 5 — CSS cleanup

In `style.css` remove the `.bf-modal` class (which set fixed width/height on the modal content). The panel's own `.details-panel` styles and the inline `width: 580px` handle sizing.

---

## BUG-52

### Activity Log for Web Workspace SiteMap & DirFuzz Panels

#### Root Cause Analysis

The Web Vulnerability Scanner panel (`#webapp-panel-scanner`) has a polished activity log (lines 2069–2075 in `index.html`):
- Collapsible with toggle button
- Ring-buffer capped at 500 entries (`ACTIVITY_MAX = 500`)
- Per-probe entries with timestamp, method, module chip, URL, hit count
- Auto-scroll; auto-expands on scan start
- Clear button

The **SiteMap** crawler panel (`#webapp-panel-sitemap`) and the **DirFuzz** panel (`#dirfuzz-panel`) have no equivalent — only a single numeric progress bar.

##### SiteMap

The crawler backend already emits `CRAWLER_URL_FOUND` and `CRAWLER_FORM_FOUND` events via IPC. These carry `{ url, status, depth, title?, method? }` and `{ action, method, inputs[] }` payloads. The renderer `sitemap.js` handles these for the tree view but does not log them as activity entries.

**No new backend changes are needed for SiteMap** — activity entries can be synthesised from existing `onUrlFound` and `onFormFound` events.

##### DirFuzz

The DirFuzz backend (`src/main/dirFuzzer.js`) exposes `startDirFuzz(opts, onHit, onProgress, onComplete, onError)`. It only fires `onHit` for paths that returned a response (not for every attempt). The renderer `dirFuzz.js` displays hits in a results table but has no per-request probe log.

To provide per-request activity (both attempted and hit), we need to:
1. Add an `onActivity` callback to `startDirFuzz`
2. Add `DIRFUZZ_ACTIVITY` IPC channel
3. Wire it through `webappIpc.js` (or the existing `fileIpc.js` / `ipc/scanIpc.js`)
4. Expose `onActivity` in the preload bridge
5. Handle it in the renderer

#### Affected Files — SiteMap

| File | Change |
|------|--------|
| `src/renderer/index.html` | Add `#sitemap-activity-wrap` section inside `#webapp-panel-sitemap` |
| `src/renderer/modules/webapp/sitemap.js` | Add activity state, `_onActivityEntry`, `_appendActivityEntry`, toggle/clear wiring |
| `src/renderer/webapp.css` | Reuse existing `.scanner-activity-*` classes (or add `.sitemap-activity-*` aliases) |

#### Affected Files — DirFuzz

| File | Change |
|------|--------|
| `src/shared/ipc.js` | Add `DIRFUZZ_ACTIVITY: 'dirfuzz-activity'` |
| `src/main/dirFuzzer.js` | Add `onActivity` param to `startDirFuzz`; emit per-probe activity events |
| `src/main/ipc/fileIpc.js` (or equivalent handler file) | Pass `onActivity` callback through to `startDirFuzz`; send `DIRFUZZ_ACTIVITY` |
| `src/main/preload.js` | Add `onActivity: (cb) => ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_ACTIVITY, ...)` to dirFuzz bridge |
| `src/renderer/modules/dirFuzz.js` | Subscribe `onActivity`; add activity log state and DOM rendering |
| `src/renderer/index.html` | Add `#dirfuzz-activity-wrap` inside `#dirfuzz-panel` |
| `src/renderer/style.css` | Ensure `.activity-*` CSS classes are accessible (move shared rules to a common location if needed) |

#### Detailed Implementation Steps

##### SiteMap — Step 1: HTML additions in `index.html`

Inside `#webapp-panel-sitemap`, **after** the progress bar (`#sitemap-progress-wrap`) and **before** the tree/results area:

```html
<!-- SiteMap Activity Log -->
<div id="sitemap-activity-wrap" class="scanner-activity-wrap activity-collapsed">
  <div class="scanner-activity-header">
    <button id="sitemap-activity-toggle" class="scanner-activity-toggle-btn">
      ▸ Activity Log
    </button>
    <span class="scanner-activity-hint">
      Live crawl output — each URL and form discovered
    </span>
    <button id="sitemap-activity-clear" class="btn secondary scanner-activity-clear-btn">
      Clear Log
    </button>
  </div>
  <div id="sitemap-activity-list" class="scanner-activity-list"></div>
</div>
```

##### SiteMap — Step 2: `sitemap.js` activity log implementation

```js
// ─── Activity Log ──────────────────────────────────────────────────────────
const ACTIVITY_MAX = 500;
let _activityLog  = [];

let $activityWrap, $activityList, $activityToggle, $activityClear;

// Called during init() after DOM refs are resolved:
function _initActivityRefs() {
  $activityWrap   = document.getElementById('sitemap-activity-wrap');
  $activityList   = document.getElementById('sitemap-activity-list');
  $activityToggle = document.getElementById('sitemap-activity-toggle');
  $activityClear  = document.getElementById('sitemap-activity-clear');

  $activityToggle?.addEventListener('click', () => {
    const collapsed = $activityWrap.classList.toggle('activity-collapsed');
    $activityToggle.textContent = collapsed ? '▸ Activity Log' : '▾ Activity Log';
  });
  $activityClear?.addEventListener('click', () => {
    _activityLog = [];
    if ($activityList) $activityList.innerHTML = '';
  });
}

function _pushActivity(entry) {
  _activityLog.push(entry);
  if (_activityLog.length > ACTIVITY_MAX) _activityLog.shift();
  _appendActivityEntry(entry);
  // Auto-expand on first entry when crawl starts
  if ($activityWrap?.classList.contains('activity-collapsed')) {
    $activityWrap.classList.remove('activity-collapsed');
    if ($activityToggle) $activityToggle.textContent = '▾ Activity Log';
  }
}

function _appendActivityEntry(entry) {
  if (!$activityList) return;
  const row = document.createElement('div');
  row.className = `activity-entry activity-${entry.kind}`;

  const shortUrl = (() => {
    try {
      const u = new URL(entry.url);
      const p = u.pathname;
      return u.hostname + (p.length > 40 ? p.slice(0, 40) + '…' : p);
    } catch { return entry.url ?? ''; }
  })();

  const ts   = new Date(entry.timestamp).toLocaleTimeString();
  const icon = entry.kind === 'form' ? '📋'
             : entry.kind === 'api'  ? '🔌'
             : entry.kind === 'error'? '✗'
             : '→';

  row.innerHTML = `
    <span class="activity-ts">${ts}</span>
    <span class="activity-status-icon">${icon}</span>
    <span class="activity-module-chip activity-chip-${entry.kind}">${entry.kind.toUpperCase()}</span>
    <span class="activity-url" title="${entry.url ?? ''}">${shortUrl}</span>
    ${entry.depth != null
      ? `<span class="activity-desc" style="color:var(--text-muted)">depth ${entry.depth}</span>`
      : ''}
    ${entry.status
      ? `<span class="activity-hit">${entry.status}</span>`
      : ''}`;

  $activityList.appendChild(row);
  $activityList.scrollTop = $activityList.scrollHeight;
}
```

**Wire into existing IPC listeners** inside `_subscribeIpc()`:

```js
// In the existing onUrlFound handler, ADD:
api.sitemap.onUrlFound((data) => {
  // existing tree-update code ...
  _pushActivity({
    kind:      'url',
    url:       data.url,
    status:    data.statusCode ? String(data.statusCode) : undefined,
    depth:     data.depth,
    timestamp: Date.now(),
  });
});

api.sitemap.onFormFound((data) => {
  // existing form-update code ...
  _pushActivity({
    kind:      'form',
    url:       data.action ?? '',
    status:    data.method?.toUpperCase(),
    timestamp: Date.now(),
  });
});

// On crawl error:
api.sitemap.onError((err) => {
  _pushActivity({
    kind:      'error',
    url:       '',
    status:    err?.message ?? 'Error',
    timestamp: Date.now(),
  });
});

// Clear activity log when a new crawl starts:
api.sitemap.onStart?.(() => {    // add onStart if not present, or use existing start button click handler
  _activityLog = [];
  if ($activityList) $activityList.innerHTML = '';
});
```

##### DirFuzz — Step 1: `ipc.js` new channel

```js
// In IPC_CHANNELS, after DIRFUZZ_ERROR:
DIRFUZZ_ACTIVITY: 'dirfuzz-activity',   // main → renderer: per-probe activity event
```

##### DirFuzz — Step 2: `dirFuzzer.js` backend

Add `onActivity` as the 6th parameter of `startDirFuzz`:

```js
export async function startDirFuzz(opts, onHit, onProgress, onComplete, onError, onActivity) {
  // ...existing setup...

  // Inside the per-path fetch loop, before the fetch call:
  onActivity?.({
    status:    'start',
    url:       probeUrl,
    method:    'GET',
    timestamp: Date.now(),
  });

  // After response received (whether hit or not):
  onActivity?.({
    status:     'done',
    url:        probeUrl,
    method:     'GET',
    statusCode: res.status,
    isHit:      HIT_CODES.includes(res.status),  // existing hit detection
    timestamp:  Date.now(),
  });
}
```

Emit `done` activity for **every** probe (not just hits) so the log shows full throughput. Hits will be distinguishable by `isHit: true`.

##### DirFuzz — Step 3: IPC handler

In the IPC handler that calls `startDirFuzz` (in `fileIpc.js` or whichever file handles `DIRFUZZ_START`), add the `onActivity` callback:

```js
startDirFuzz(
  opts,
  (hit) => win?.webContents.send(IPC_CHANNELS.DIRFUZZ_HIT, hit),
  (progress) => win?.webContents.send(IPC_CHANNELS.DIRFUZZ_PROGRESS, progress),
  (result) => win?.webContents.send(IPC_CHANNELS.DIRFUZZ_COMPLETE, result),
  (err) => win?.webContents.send(IPC_CHANNELS.DIRFUZZ_ERROR, { message: err?.message }),
  (activity) => win?.webContents.send(IPC_CHANNELS.DIRFUZZ_ACTIVITY, activity),  // ← add
);
```

##### DirFuzz — Step 4: Preload bridge

In `src/main/preload.js`, inside the `dirFuzz` bridge object:

```js
dirFuzz: {
  // ... existing channels ...
  onActivity: (cb) => ipcRenderer.on(IPC_CHANNELS.DIRFUZZ_ACTIVITY, (_e, v) => cb(v)),
},
```

Also add the channel to the `removeListeners` cleanup list.

##### DirFuzz — Step 5: HTML in `index.html`

Inside `#dirfuzz-panel`, **after** the progress bar and **before** the results table:

```html
<!-- Dir Fuzzer Activity Log -->
<div id="dirfuzz-activity-wrap" class="scanner-activity-wrap activity-collapsed">
  <div class="scanner-activity-header">
    <button id="dirfuzz-activity-toggle" class="scanner-activity-toggle-btn">
      ▸ Activity Log
    </button>
    <span class="scanner-activity-hint">
      Per-request probe log — highlighted rows are hits
    </span>
    <button id="dirfuzz-activity-clear" class="btn secondary scanner-activity-clear-btn">
      Clear Log
    </button>
  </div>
  <div id="dirfuzz-activity-list" class="scanner-activity-list"></div>
</div>
```

##### DirFuzz — Step 6: `dirFuzz.js` renderer activity implementation

Mirror the `sitemap.js` pattern exactly. Add at module level:

```js
const ACTIVITY_MAX = 1000;   // dir fuzz generates more events
let _activityLog  = [];
let $activityWrap, $activityList, $activityToggle, $activityClear;
```

In `init()` / DOM binding:

```js
$activityWrap   = document.getElementById('dirfuzz-activity-wrap');
$activityList   = document.getElementById('dirfuzz-activity-list');
$activityToggle = document.getElementById('dirfuzz-activity-toggle');
$activityClear  = document.getElementById('dirfuzz-activity-clear');

$activityToggle?.addEventListener('click', () => {
  const c = $activityWrap.classList.toggle('activity-collapsed');
  $activityToggle.textContent = c ? '▸ Activity Log' : '▾ Activity Log';
});
$activityClear?.addEventListener('click', () => {
  _activityLog = [];
  if ($activityList) $activityList.innerHTML = '';
});
```

IPC subscription:

```js
api.dirFuzz.onActivity(_onActivity);
```

Handler:

```js
function _onActivity(ev) {
  _activityLog.push(ev);
  if (_activityLog.length > ACTIVITY_MAX) _activityLog.shift();

  if (!$activityList) return;

  // Throttle DOM writes: only render every 10th entry during hot fuzzing
  // to avoid layout thrashing; always render hits immediately
  if (!ev.isHit && _activityLog.length % 10 !== 0) return;

  const row = document.createElement('div');
  const statusClass = ev.isHit ? 'activity-done' : 'activity-start';
  row.className = `activity-entry ${statusClass}`;

  const shortPath = (() => {
    try { return new URL(ev.url).pathname; }
    catch { return ev.url ?? ''; }
  })();

  row.innerHTML = `
    <span class="activity-ts">${new Date(ev.timestamp).toLocaleTimeString()}</span>
    <span class="activity-status-icon">${ev.isHit ? '✓' : '→'}</span>
    <span class="activity-method">${ev.method ?? 'GET'}</span>
    <span class="activity-module-chip activity-chip-${ev.isHit ? 'xss' : ''}"
          style="min-width:40px; text-align:center;">
      ${ev.statusCode ?? '…'}
    </span>
    <span class="activity-url" title="${ev.url ?? ''}">${shortPath}</span>`;

  if (ev.isHit) {
    row.style.background = 'rgba(46, 213, 115, 0.08)';
    // Auto-expand on first hit
    if ($activityWrap?.classList.contains('activity-collapsed')) {
      $activityWrap.classList.remove('activity-collapsed');
      if ($activityToggle) $activityToggle.textContent = '▾ Activity Log';
    }
  }
  $activityList.appendChild(row);
  $activityList.scrollTop = $activityList.scrollHeight;
}
```

> **Note on throttling:** DirFuzz can probe thousands of paths per second. Writing a DOM node per probe will freeze the UI. The `% 10` throttle above renders every 10th non-hit entry; hits are always rendered immediately. An alternative is a `requestAnimationFrame` flush queue (batch DOM writes into a single rAF). Either pattern is acceptable; choose based on target wordlist size.

##### Shared CSS (`webapp.css` or `style.css`)

The `.scanner-activity-*` classes are already defined in `webapp.css`. The new SiteMap and DirFuzz activity logs reuse them entirely. No new CSS rules are needed **if** the existing classes are defined globally. If they are scoped to the scanner panel, extract them into a shared block accessible from both workspaces:

```css
/* Shared activity log — used by scanner, sitemap, dirfuzz */
.scanner-activity-wrap {
  border-top: 1px solid var(--border-glass);
  background: rgba(0,0,0,0.2);
  flex-shrink: 0;
  max-height: 260px;
  display: flex;
  flex-direction: column;
  transition: max-height 0.3s ease;
}
.scanner-activity-wrap.activity-collapsed {
  max-height: 32px;
  overflow: hidden;
}
.scanner-activity-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  flex-shrink: 0;
}
.scanner-activity-toggle-btn {
  background: none; border: none; cursor: pointer;
  color: var(--accent); font-size: 12px; padding: 0;
}
.scanner-activity-hint {
  font-size: 10px; color: var(--text-muted); flex: 1;
}
.scanner-activity-clear-btn { font-size: 10px; padding: 2px 8px; }
.scanner-activity-list {
  overflow-y: auto; flex: 1;
  font-size: 11px; font-family: monospace;
}
.activity-entry {
  display: flex; align-items: baseline; gap: 6px;
  padding: 2px 12px; border-bottom: 1px solid rgba(255,255,255,0.03);
  white-space: nowrap; overflow: hidden;
}
.activity-entry:hover { background: rgba(255,255,255,0.04); }
.activity-done .activity-status-icon { color: var(--success); }
.activity-start .activity-status-icon { color: var(--text-muted); }
.activity-ts    { color: var(--text-muted); min-width: 70px; font-size: 10px; }
.activity-method { color: var(--accent-secondary); min-width: 36px; }
.activity-module-chip {
  font-size: 9px; padding: 1px 5px; border-radius: 3px;
  background: rgba(255,255,255,0.07); white-space: nowrap;
}
.activity-url  { color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; flex: 1; }
.activity-hit  { color: var(--danger); font-size: 10px; font-weight: 700; white-space: nowrap; }
.activity-desc { color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; flex: 1; }
```

---

## Cross-Cutting Concerns

### Security

- **BUG-50:** `_esc()` must sanitise all host metadata before injecting into the host details DOM (`innerHTML`). Use the existing `_esc` helper or a validated DOM API (`textContent`, `createElement`). Never inject `finding.url`, `finding.title`, or `finding.description` via raw `innerHTML` without escaping.
- **BUG-51:** All existing brute-force input validation (IP regex, port range) must be preserved. The panel refactor is purely structural — no security logic changes.
- **BUG-52:** Activity log entries rendered with `innerHTML` must escape user-controlled strings (especially `ev.url` which could be a redirect to an attacker-controlled page that reflects strings back). Use `_esc()` or set via `textContent`.

### IPC Payloads

- Keep `DIRFUZZ_ACTIVITY` payloads lean: `{ status, url, method, statusCode, isHit, timestamp }` — no response bodies. Serialisation overhead at 1000+ probes/sec is measurable.
- `webVulnFindings` stored on hosts must survive `JSON.stringify` — no circular refs, no DOM elements.

### Memory

- DirFuzz ring buffer capped at 1000 entries (`ACTIVITY_MAX = 1000`). After cap, oldest entries drop (FIFO shift).
- SiteMap cap at 500.
- Host `webVulnFindings` capped at 200 per host before session save.

---

## Test Coverage Plan

### BUG-50 Tests

**File:** `test/renderer/scanner.test.js` (new or extend existing)

| Test | What to assert |
|------|----------------|
| `_updateNetworkBadge` — existing host matched by IP | `host.webVulnCount === 1`; badge text contains count |
| `_updateNetworkBadge` — called twice on same host | count increments to 2; badge text updated, not duplicated |
| `_updateNetworkBadge` — host matched by hostname | `host.hasWebVulns === true`; badge injected on correct card |
| `_updateNetworkBadge` — no matching host | new stub host added to `state.hosts`; `network:hostAdded` event fired |
| `reapplyWebVulnBadges` — post re-render | badges re-injected on all `hasWebVulns` hosts |
| `getSecurityBadgeData` — host with critical web finding | returns `badgeClass: 'danger'`; icon `'🌐'` |
| `getSecurityBadgeData` — host with low web finding | returns `badgeClass: 'warning'` |
| `renderWebVulnSection` — empty findings | section hidden |
| `renderWebVulnSection` — 3 findings, sorted by severity | critical first; HTML escaping applied |
| Session persistence | `webVulnFindings` survives `JSON.stringify(state.hosts)` roundtrip |

### BUG-51 Tests

**File:** `test/renderer/bruteForce.test.js` (extend)

| Test | What to assert |
|------|----------------|
| `openBruteForcePanel(ip, port, protocol)` | panel `display` → `flex`; resizer `display` → `block` |
| Close button | panel gets `display: none` after 300ms |
| Pre-fill IP | `#bf-target-ip.value === ip` |
| Panel does not block rest of UI | no modal overlay in DOM |
| Existing start/stop/result logic unchanged | existing tests still pass |

### BUG-52 Tests

**File:** `test/renderer/sitemap.test.js` (new) and `test/renderer/dirFuzz.test.js` (extend)

| Test | What to assert |
|------|----------------|
| SiteMap `onUrlFound` → activity entry | entry appended to `#sitemap-activity-list` |
| SiteMap `onFormFound` → activity entry | kind chip shows `FORM` |
| SiteMap ring buffer cap | after 500 entries oldest dropped |
| SiteMap clear button | list innerHTML emptied; `_activityLog` = `[]` |
| SiteMap auto-expand | collapsed class removed on first url-found |
| DirFuzz `onActivity` hit | entry added with `isHit: true` flag; green highlight |
| DirFuzz throttle | 10 non-hit events → only 1 DOM node appended |
| DirFuzz ring buffer cap 1000 | oldest dropped |
| `dirFuzzer.js` `onActivity` callback called | spy receives start + done events for each probe |
| `DIRFUZZ_ACTIVITY` IPC channel constant | exists in `ipc.js` |

---

## Implementation Order & Dependencies

```
1. BUG-52a — Add DIRFUZZ_ACTIVITY to ipc.js                   (no deps)
2. BUG-52b — dirFuzzer.js backend onActivity                   (needs step 1)
3. BUG-52c — IPC handler wire-up                               (needs step 2)
4. BUG-52d — preload bridge                                     (needs step 1)
5. BUG-52e — index.html dirfuzz-activity-wrap                  (no deps)
6. BUG-52f — dirFuzz.js renderer activity log                  (needs steps 4, 5)
7. BUG-52g — index.html sitemap-activity-wrap                  (no deps)
8. BUG-52h — sitemap.js activity log                           (needs step 7)
9. BUG-52i — Shared CSS rules for activity-* classes           (no deps, do early)

10. BUG-51a — index.html: remove modal, add panel+resizer       (no deps)
11. BUG-51b — bruteForce.js: modal→panel migration              (needs step 10)
12. BUG-51c — hostDetails.js: update openBruteForcePanel call  (needs step 11)
13. BUG-51d — style.css: remove .bf-modal, verify panel CSS     (needs step 10)

14. BUG-50a — scanner.js: _attachFindingToHost + count badge    (no deps)
15. BUG-50b — scanner.js: export reapplyWebVulnBadges           (needs step 14)
16. BUG-50c — index.js: wire reapplyWebVulnBadges               (needs step 15)
17. BUG-50d — scanControls.js: getSecurityBadgeData web tier    (needs step 14)
18. BUG-50e — index.html: #host-webvuln-section markup          (no deps)
19. BUG-50f — hostDetails.js: renderWebVulnSection              (needs step 18)
20. BUG-50g — webapp.css / style.css: webvuln styles            (no deps)
21. BUG-50h — fileIpc.js: cap webVulnFindings on save           (no deps)
22. BUG-50i — session load: reapplyWebVulnBadges call           (needs step 15)
```

BUG-52 can be worked in parallel with BUG-51. BUG-50 depends only on its own chain and can proceed independently of the other two.
