# Project Rules

> Rules for the Antigravity agent. Loaded from `.agent/rules/`.

# Electron Desktop Application Agent Rules

## Project Context
You are working on an Electron desktop application using Javascript, with a clear separation between the main process, renderer process, and preload scripts.

## Code Style & Structure
- Write Javscript throughout all processes (main, renderer, preload).
- Use descriptive names with auxiliary verbs (e.g., isMaximized, hasUnsavedChanges, canClose).
- Prefer named exports for modules, services, and utilities.
- Keep main process code synchronous-style where possible; use async/await for I/O operations.
- Follow consistent file naming: `kebab-case.js` for modules, `PascalCase.tsx` for React/Vue components.
- Use path aliases (`@main/`, `@renderer/`, `@shared/`) to keep imports clean across process boundaries.

## Project Structure
- Separate code by process: `src/main/` for the main process, `src/renderer/` for the UI, `src/preload/` for preload scripts.
- Place shared types and constants in `src/shared/` accessible by all processes.
- Store static assets (icons, tray images) in `resources/` outside the source directory.
- Define IPC channel names and payload types in `src/shared/ipc.js` as a single source of truth.
- Keep the main process entry point (`src/main/index.js`) focused on app lifecycle and window creation.
- Organize renderer code like a standard web app: components, pages, hooks, stores, utils.

## IPC Communication
- Define all IPC channels as typed string constants in a shared module. Never use inline string channel names.
- Use `contextBridge.exposeInMainWorld` in preload scripts to create a typed API object on `window`.
- Define an interface for the exposed API and augment the `Window` interface in a `.d.ts` file.
- Use `ipcMain.handle` / `ipcRenderer.invoke` for request-response patterns (returns a Promise).
- Use `ipcMain.on` / `webContents.send` for one-way main-to-renderer notifications (e.g., menu events).
- Validate all data received over IPC in the main process. Never trust renderer input.
- Keep IPC payloads serializable (JSON-compatible). Avoid passing complex objects or class instances.
- Batch frequent IPC calls to avoid performance overhead from excessive serialization.

## Security
- Set `nodeIntegration: false` and `contextIsolation: true` on all `BrowserWindow` instances. No exceptions.
- Never expose Node.js APIs directly to the renderer. Use preload scripts with `contextBridge` exclusively.
- Implement a strict Content Security Policy (CSP) in the HTML or via `session.defaultSession.webRequest`.
- Disable `webSecurity` only in development. Never ship with `webSecurity: false`.
- Validate and sanitize all URLs before loading with `win.loadURL()`. Use an allowlist for external navigations.
- Use `shell.openExternal` with URL validation for opening links in the system browser.
- Disable `remote` module entirely. It is deprecated and a security risk.
- Disable `allowRunningInsecureContent` and `experimentalFeatures` in production builds.

## Window Management
- Create windows via a factory function that applies consistent defaults (size, icon, webPreferences).
- Save and restore window bounds (position, size, maximized state) using `electron-store` or a settings file.
- Handle multi-window scenarios with a window manager that tracks all open windows by ID.
- Use `BrowserWindow` events (`close`, `focus`, `blur`, `resize`) to manage application state.
- Implement proper cleanup on window close: save state, release resources, remove IPC listeners.
- Use `Menu.buildFromTemplate` for native menus. Dynamically update menu items based on app state.
- Support system tray with `Tray` for background operation when the user closes the main window.

## Auto-Updates
- Use `electron-updater` (from `electron-builder`) for cross-platform automatic updates.
- Configure update channels: `latest` for stable, `beta` for pre-release, `alpha` for internal testing.
- Check for updates on app start and periodically. Notify the user before installing.
- Handle update events: `update-available`, `download-progress`, `update-downloaded`.
- Allow the user to defer updates. Apply downloaded updates on the next app restart.
- Sign all releases for macOS (notarization) and Windows (code signing) to avoid OS security warnings.
- Test the update flow end-to-end with a staging update server before releasing.

## Packaging & Distribution
- Use `electron-builder` for cross-platform packaging (DMG, NSIS, AppImage, Snap).
- Define build configuration in `electron-builder.yml` or `package.json` under `build`.
- Exclude development files from the packaged app with `files` patterns in build config.
- Use ASAR archives for source code (enabled by default). Exclude native modules from ASAR.
- Optimize app size: audit dependencies, tree-shake unused code, compress assets.
- Set up CI to build platform-specific artifacts: macOS on macOS runners, Windows on Windows runners.
- Publish releases to GitHub Releases, S3, or a custom update server.

## Testing
- Test main process logic (IPC handlers, file operations, services) with Vitest or Jest.
- Test renderer UI components with React Testing Library or the framework's test utilities.
- Write integration tests for IPC round-trips using a test harness that spawns the Electron app.
- Use Playwright or Spectron for end-to-end tests that exercise the full application.
- Mock Electron APIs (`dialog`, `shell`, `app`) in unit tests with `vi.mock("electron")`.
- Test platform-specific behavior (macOS menu bar, Windows tray) in CI on the appropriate OS.

## Performance
- Lazy-load renderer modules and routes to minimize startup time.
- Move CPU-intensive tasks to worker threads (`worker_threads`) or utility processes.
- Profile memory usage with Chrome DevTools. Watch for leaks from unreleased IPC listeners.
- Use `requestIdleCallback` and `requestAnimationFrame` for non-critical UI updates.
- Minimize the main process workload; delegate heavy computation to child processes.
- Monitor and limit the number of open `BrowserWindow` instances to control memory consumption.
- Use `v8-compile-cache` or snapshot-based optimizations for faster main process startup.

## Documentation
- Maintain feature and developer friendly readme.md file
- Maintain a getting-started-guide.md that describes in detail how to get started, every feature and option.