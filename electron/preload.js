// Безопасный мост для автокопий: страница может только сохранить файл копии
// в «Документы\\SamHelp-backups» и открыть эту папку.
const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("samhelp", {
  loadState: () => ipcRenderer.invoke("samhelp:load-state"),
  saveState: (text) => ipcRenderer.invoke("samhelp:save-state", text),
  saveBackup: (name, text) => ipcRenderer.invoke("samhelp:save-backup", name, text),
  openBackupFolder: () => ipcRenderer.invoke("samhelp:open-backup-folder")
});
