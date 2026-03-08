import { IPC_CHANNELS } from '#shared/ipc.js';
import { getSetting, setSetting, getAllSettings, checkDependency } from '../store.js';

export function registerIpcHandlers(ipcMain, _getWindow) {
  ipcMain.handle(IPC_CHANNELS.GET_SETTING, (_event, key) => {
    return getSetting(key);
  });

  ipcMain.handle(IPC_CHANNELS.SET_SETTING, (_event, { key, value }) => {
    setSetting(key, value);
    return { success: true };
  });

  ipcMain.handle(IPC_CHANNELS.GET_ALL_SETTINGS, () => {
    return getAllSettings();
  });

  ipcMain.handle(IPC_CHANNELS.CHECK_DEPENDENCY, async (_event, toolName) => {
    return await checkDependency(toolName);
  });
}
