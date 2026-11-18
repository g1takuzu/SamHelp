const { app, BrowserWindow, shell, ipcMain } = require("electron");
const path = require("node:path");
const fs = require("node:fs");

const APP_URL = path.join(__dirname, "..", "app", "index.html");
const EXTERNAL_SCHEMES = /^(https?:|mailto:|tel:|tg:|whatsapp:|ms-|calculator:)/i;

// Постоянное хранилище приложения в профиле пользователя Windows.
const STATE_FILE = () => path.join(app.getPath("userData"), "SamHelp-state.json");
let stateWriteQueue = Promise.resolve();

ipcMain.handle("samhelp:load-state", async () => {
  try {
    return await fs.promises.readFile(STATE_FILE(), "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
});
ipcMain.handle("samhelp:save-state", async (_event, text) => {
  if (typeof text !== "string" || text.length > 50 * 1024 * 1024) throw new Error("bad state data");
  stateWriteQueue = stateWriteQueue.then(async () => {
    const file = STATE_FILE();
    await fs.promises.mkdir(path.dirname(file), { recursive: true });
    const temp = file + ".tmp";
    await fs.promises.writeFile(temp, text, "utf8");
    await fs.promises.rename(temp, file);
  });
  await stateWriteQueue;
  return true;
});

// Автокопии: программа кладёт файлы-копии в «Документы\\SamHelp-backups»
function backupDir() {
  const dir = path.join(app.getPath("documents"), "SamHelp-backups");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}
ipcMain.handle("samhelp:save-backup", async (_event, name, text) => {
  if (typeof name !== "string" || !/^samhelp-[\w.\-]+\.json$/.test(name)) throw new Error("bad name");
  if (typeof text !== "string" || text.length > 50 * 1024 * 1024) throw new Error("bad data");
  const dir = backupDir();
  await fs.promises.writeFile(path.join(dir, name), text, "utf8");
  // храним последние 30 файлов
  const files = (await fs.promises.readdir(dir)).filter((f) => /^samhelp-.*\.json$/.test(f)).sort();
  for (const f of files.slice(0, Math.max(0, files.length - 30))) {
    await fs.promises.unlink(path.join(dir, f)).catch(() => {});
  }
  return dir;
});
ipcMain.handle("samhelp:open-backup-folder", async () => {
  await shell.openPath(backupDir());
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1280, height: 850, minWidth: 900, minHeight: 650,
    show: false, autoHideMenuBar: true, backgroundColor: "#f7f3f5",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true, nodeIntegration: false, sandbox: true
    }
  });
  win.once("ready-to-show", () => win.show());
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (EXTERNAL_SCHEMES.test(url)) shell.openExternal(url).catch(() => {});
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (event, url) => {
    if (url.startsWith("file://")) return;
    event.preventDefault();
    if (EXTERNAL_SCHEMES.test(url)) shell.openExternal(url).catch(() => {});
  });
  win.loadFile(APP_URL);
}
app.whenReady().then(() => {
  app.setAppUserModelId("ru.moikontakty.desktop");
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
