# NetSpecter Refactoring & Tech Debt Plan

> Code review performed: 2026-03-08
> Reviewer: Claude Code (Sonnet 4.6)
> Branch reviewed: `cred-spray`

---

## Executive Summary

NetSpecter is a well-architected Electron application with clear separation between main/renderer/preload processes, a shared IPC channel constants file, and comprehensive unit tests. The main process modules are appropriately sized (50–500 lines each). The critical structural problem is the **renderer** — `index.js` at **6,383 lines** is a monolith that makes the renderer nearly impossible to navigate, extend, or test in isolation.

Secondary issues include `main.js` registering all 39+ IPC handlers in one place (good for discoverability, but each handler body should move to its feature module), scattered magic values, and inconsistent validation patterns.

---

## Codebase Stats

| Layer | Files | Lines |
|-------|-------|-------|
| `src/main/` (main process) | 27 | 5,231 |
| `src/renderer/` (renderer process) | 6 | 6,993 |
| `src/shared/` (constants/IPC) | 2 | 413 |
| `test/` | 29 | 6,072 |
| **Total source** | **64** | **18,709** |

The renderer (6 files, 6,993 lines) contains **37% of all source code** but handles only UI logic — rendering, event handling, and panel state — that should be modular.

---

## Priority 1 — Split `src/renderer/index.js` (6,383 lines → 12 modules)

This is the single most impactful refactor. A 6,383-line file means:
- No file-level searchability: you cannot know what's in the file without reading it
- Every feature change touches the same file, guaranteeing merge conflicts
- Tests cannot import a single feature in isolation
- New contributors cannot orient themselves

### Is this file size normal for Electron/Vite apps?

No. Large Electron apps (VS Code, Figma, Slack) split their renderer into hundreds of component/module files via frameworks (React, Vue, Svelte) or module bundlers. A single monolithic renderer controller is an anti-pattern at any scale above ~500 lines. Vite (which this project already uses) makes code-splitting trivial.

### Proposed Renderer Module Split

Create `src/renderer/modules/` and split by feature. Each module exports an `init()` function that receives element references and the API, binds its own events, and returns a public interface if other modules need to call it.

```
src/renderer/
├── index.js                     (< 150 lines — orchestrator only)
├── api.js                       (keep as-is, 84 lines)
├── state.js                     (keep as-is, 23 lines)
├── ui.js                        (keep as-is, 116 lines)
├── topology.js                  (keep as-is, 313 lines)
├── scanAllOrchestrator.js       (keep as-is, 74 lines)
└── modules/
    ├── init.js                  (~80 lines)  — dependency checks, banner, CSS class toggling
    ├── settings.js              (~200 lines) — settings modal, tool toggles, sync
    ├── scanControls.js          (~350 lines) — network scan, CIDR input, blacklist, host grid/table/list
    ├── hostDetails.js           (~600 lines) — host details panel, port actions, vuln display
    ├── deepScan.js              (~250 lines) — deep scan triggers, results rendering
    ├── passiveIntel.js          (~400 lines) — passive capture tab, DHCP/creds/DNS/ARP/PCAP display
    ├── pcap.js                  (~200 lines) — PCAP live capture, file import
    ├── hardeningMonitor.js      (~500 lines) — baseline management, delta alerts, investigation UI
    ├── credSpray.js             (~400 lines) — spray panel, protocol selection, hits table
    ├── bruteForce.js            (~250 lines) — brute-force modal, progress, wordlist picker
    ├── metasploit.js            (~250 lines) — MSF connection modal, exploit runner, session list
    ├── revShell.js              (~150 lines) — reverse shell panel, command prompt
    └── shareEnum.js             (~200 lines) — share browser panel, breadcrumb nav, file download
```

**Estimated reduction in `index.js`**: 6,383 lines → ~150 lines (97% reduction).

### Module Contract Pattern

Each module file follows this pattern:

```javascript
// src/renderer/modules/bruteForce.js

import { api } from '../api.js';
import { state } from '../state.js';
import { elements } from '../ui.js';

export function init() {
  // bind events local to this module
  elements.btnBruteforceOpen?.addEventListener('click', openModal);
  api.onBruteForceResult(handleResult);
  api.onBruteForceProgress(handleProgress);
  api.onBruteForceComplete(handleComplete);
  api.onBruteForceError(handleError);

  return {
    openModal,         // exposed so hostDetails.js can call it with a pre-filled IP
    closeModal,
  };
}

function openModal(ip, port, protocol) { ... }
// ... rest of brute-force UI logic
```

The new `index.js` becomes:

```javascript
import { initDependencyChecks } from './modules/init.js';
import { init as initSettings }  from './modules/settings.js';
import { init as initScan }      from './modules/scanControls.js';
// ... other module imports

(async () => {
  const deps = await initDependencyChecks();
  const settings   = initSettings(deps);
  const scan       = initScan(deps);
  const hostDetails = initHostDetails({ scan, bruteForce, dirFuzz, shareEnum });
  initPassiveIntel(deps);
  initHardeningMonitor();
  initCredSpray();
  const bruteForce = initBruteForce();
  initMetasploit();
  initRevShell();
  initShareEnum();
  initDirFuzz();
})();
```

### Cross-Module Communication

Modules that need to open panels from other modules (e.g., host details card has "Brute Force" button) should receive references at init time:

```javascript
const bruteForce = initBruteForce();
const dirFuzz    = initDirFuzz();
initHostDetails({ bruteForce, dirFuzz, shareEnum, credSpray });
```

This avoids global `window.__openXPanel()` hacks currently used.

---

## Priority 2 — Slim `src/main/main.js` (932 lines → ~150 lines)

`main.js` correctly imports from feature modules, but it contains the handler bodies inline rather than delegating them. The file has grown as each new feature added 20–50 lines of handler logic directly.

### Current pattern (each handler is 15–40 lines):

```javascript
ipcMain.handle(IPC_CHANNELS.DIRFUZZ_START, async (event, opts) => {
  // 30 lines of validation + routing logic
});
```

### Better pattern — move logic to feature modules:

Each feature module exports a `registerIpcHandlers(ipcMain, mainWindow)` function.

```javascript
// src/main/dirFuzzer.js  (add to bottom)
export function registerIpcHandlers(ipcMain, getWindow) {
  ipcMain.handle(IPC_CHANNELS.DIRFUZZ_START, async (_, opts) => { ... });
  ipcMain.handle(IPC_CHANNELS.DIRFUZZ_STOP,  async ()      => { ... });
}
```

```javascript
// src/main/main.js  (new, slim version)
import { registerIpcHandlers as registerDirFuzz } from './dirFuzzer.js';
// ...
app.whenReady().then(() => {
  mainWindow = createMainWindow();
  registerDirFuzz(ipcMain, () => mainWindow);
  registerBruteForce(ipcMain, () => mainWindow);
  // ...
});
```

**Estimated reduction**: 932 lines → ~150 lines. Each feature module grows by ~30 lines.

### Note on `snmpIpc.js`

`snmpIpc.js` (30 lines) already implements this pattern correctly via `registerSnmpHandlers()`. All other modules should follow this example.

### Proposed grouping for remaining main.js handlers

Some thin handlers (settings, file I/O, ping, CIDR operations) can be grouped into helper IPC registration files rather than living in `main.js`:

```
src/main/ipc/
├── settingsIpc.js     — GET_SETTING, SET_SETTING, GET_ALL_SETTINGS, CHECK_DEPENDENCY
├── fileIpc.js         — SAVE_RESULTS, LOAD_RESULTS, CLEAR_RESULTS, IMPORT_*, BROWSE_FILE
├── utilIpc.js         — PING_HOST, PROBE_HOST, OPEN_EXTERNAL_ACTION, EXIT_APP
```

---

## Priority 3 — Remove Dead Code

### `src/counter.js` (9 lines)

This is the Vite scaffolding example file. It is unused. Delete it.

### `src/main.js` (24 lines, root-level entry)

Verify this is the Vite entry used for renderer build (as opposed to `src/main/main.js` which is the Electron main process). If it is only a Vite entry stub that loads `src/renderer/index.js`, rename to `src/renderer/main.js` to eliminate the confusing name collision with `src/main/main.js`.

---

## Priority 4 — Centralize Validation & Constants

### Problem: `ipRegex` is duplicated

`ipRegex` is exported from `src/shared/networkConstants.js` but inline regex patterns appear in `main.js` and other files instead of importing the canonical version.

**Fix**: Grep all files for `/^(?:[0-9]{1,3}\.)/` and replace with the shared import.

### Problem: Magic port numbers scattered

HTTP ports that trigger "Dir Fuzz" buttons (80, 443, 8080, 8443, 3000, 5000, 8000, 8888) are hardcoded in the renderer. SMB ports (139, 445) are hardcoded in host details. These should live in `networkConstants.js`.

**Proposed additions to `networkConstants.js`**:

```javascript
export const HTTP_PORTS   = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888];
export const SMB_PORTS    = [139, 445];
export const TELNET_PORTS = [23];
export const FTP_PORTS    = [21];
export const SSH_PORTS    = [22];
```

### Problem: Timeout values are magic numbers

Request timeouts (5000ms, 3000ms, 10000ms) appear in dirFuzzer.js, credSprayTransports.js, and deepScanner.js without named constants.

**Proposed addition to `networkConstants.js`**:

```javascript
export const TIMEOUTS = {
  CONNECT_MS:       3_000,
  REQUEST_MS:       5_000,
  DEEP_SCAN_MS:    10_000,
  TELNET_BANNER_MS: 3_000,
};
```

---

## Priority 5 — Validation Consistency in Main Process

### Missing validation in `main.js` handlers

Several handlers receive user-controlled data from the renderer and use it without thorough validation:

| Handler | Input | Risk | Fix |
|---------|-------|------|-----|
| `SCAN_NETWORK` | CIDR string | Passed to `expandCIDR` — already protected | Low |
| `SHARE_DOWNLOAD` | `destPath` | User-supplied filesystem path | Validate is within allowed directory |
| `DIRFUZZ_START` | `targetUrl` | URL could be `file://` or internal | Validate scheme is `http://` or `https://` |
| `RUN_NMAP_SCAN` | `target` | Free-form target string | Validate IP or hostname format |
| `OPEN_EXTERNAL_ACTION` | URL | `shell.openExternal` with unvalidated URL | Allowlist `https://` scheme only |

### Recommended validation helper

Add to `src/shared/networkConstants.js` or a new `src/shared/validate.js`:

```javascript
export function isValidIpOrHostname(value) {
  return ipRegex.test(value) || /^[a-zA-Z0-9.-]{1,253}$/.test(value);
}

export function isValidHttpUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}
```

---

## Priority 6 — Structured Logging

All modules use `console.log` / `console.warn` / `console.error` inconsistently. In production builds, these are suppressed or hard to search.

### Current pattern:
```javascript
console.log('[NetSpecter] Running as root...');
console.warn('Hydra not found');
console.error('IPC handler failed:', err);
```

### Proposed minimal logger (`src/main/logger.js`):
```javascript
const isDev = process.env.NODE_ENV === 'development';

export const logger = {
  info:  (module, msg, ...args) => isDev && console.log(`[${module}] ${msg}`, ...args),
  warn:  (module, msg, ...args) => console.warn(`[${module}] ${msg}`, ...args),
  error: (module, msg, ...args) => console.error(`[${module}] ${msg}`, ...args),
};
```

This is intentionally minimal — a full logging library is not warranted for this app.

---

## Priority 7 — Remove `window.__openXPanel()` Globals

The renderer currently exposes panel-open functions on `window` to allow cross-feature calls:

```javascript
window.__openDirFuzzPanel = (url) => { ... };
window.__openSharePanel   = (ip)  => { ... };
```

These are anti-patterns that break module encapsulation and are invisible to static analysis. After the Priority 1 module split, these should be replaced by the cross-module reference pattern described in that section.

---

## Priority 8 — Test Coverage for Renderer Modules

After splitting `index.js`, add unit tests for each renderer module. Currently only `test/renderer/revshellUI.test.js` exists for renderer-side logic.

Target: One test file per renderer module, focusing on:
- DOM event binding (simulate click → assert API called)
- State mutation after IPC callbacks
- Error states (API returns error → correct error message displayed)

Use `jsdom` (already in dev deps) + `vi.mock('../api.js')`.

---

## What NOT to Refactor

- **`src/main/` individual modules** — correctly sized (50–500 lines). Do not merge or reorganize.
- **`src/shared/ipc.js`** — well-structured single source of truth. Keep as-is.
- **`src/shared/networkConstants.js`** — good home for constants. Only add, don't restructure.
- **`src/main/preload.js`** — correctly organized contextBridge bindings. Acceptable size.
- **`src/main/store.js`** — clean, well-contained. No changes needed.
- **`test/` files** — comprehensive coverage with good mock patterns. Don't refactor tests until source modules are split.
- **IPC channel names** — already well-named and organized. No changes.

---

## Implementation Order

Execute in this order to minimize risk and keep tests green throughout:

| Step | Action | Risk | Effort |
|------|--------|------|--------|
| 1 | Delete `src/counter.js` | None | Trivial |
| 2 | Add `HTTP_PORTS`, `SMB_PORTS`, port constants to `networkConstants.js` | Very low | 30 min |
| 3 | Add `TIMEOUTS` constants to `networkConstants.js` | Very low | 20 min |
| 4 | Create `src/shared/validate.js` with URL/IP validators | Low | 1 hr |
| 5 | Move each feature's IPC handler body into its source module (`registerIpcHandlers`) | Medium | 2–3 hr |
| 6 | Slim `main.js` to ~150 lines, calling `registerIpcHandlers` per module | Low after step 5 | 1 hr |
| 7 | Create `src/renderer/modules/` directory, extract one module at a time, starting with the smallest (revShell, bruteForce) | Medium | 4–6 hr total |
| 8 | Wire modules in new slim `index.js`; verify app boots and all panels function | Medium | 1–2 hr |
| 9 | Remove `window.__openXPanel()` globals; use module references | Low after step 7 | 1 hr |
| 10 | Add renderer module tests | Low | 3–4 hr |
| 11 | Fix validation gaps from Priority 5 table | Medium | 2 hr |

---

## File Size Expectations After Refactor

| File | Before | After |
|------|--------|-------|
| `src/renderer/index.js` | 6,383 | ~150 |
| `src/renderer/modules/*.js` (12 files) | 0 | ~3,600 |
| `src/main/main.js` | 932 | ~150 |
| `src/main/*/registerIpcHandlers` additions | 0 | ~500 |
| Total renderer lines | 6,383 | ~3,750 |
| Total main process lines | 5,231 | ~5,381 |
| Net change | 11,614 | ~9,131 |

Net line count decreases (~21%) due to elimination of boilerplate and duplicate patterns exposed during extraction.

---

## Answers to Specific Concerns

### "Is the line count expected for large Electron/Vite apps?"

For the **main process**: Yes. 27 files averaging ~190 lines each is normal for a feature-rich Electron backend. Each file is focused on one concern.

For the **renderer**: No. A 6,383-line monolithic controller is not expected or necessary. Electron apps of similar scale use either a frontend framework (React/Vue/Svelte) with component files, or at minimum split their vanilla JS renderer by feature. Vite's module system makes splitting trivial — there is no technical barrier, only the accumulation of features into one file over time.

### "Should we migrate to React/Vue?"

Not recommended at this time. The app is working, tested, and has a clear glassmorphic UI identity. Migrating the renderer to a framework would require rewriting all 6,383 lines of UI logic. The module-split approach in Priority 1 achieves 90% of the maintainability benefit with far less risk and effort.

If a major UI redesign is planned (e.g., for a 2.0 release), that would be the right time to adopt a component framework.

---

*End of REFACTOR.md*
