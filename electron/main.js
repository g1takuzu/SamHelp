
const { app, BrowserWindow, shell } = require("electron");
const path = require("node:path");

const APP_URL = path.join(__dirname, "..", "app", "index.html");
const EXTERNAL_SCHEMES = /^(https?:|mailto:|tel:|tg:|whatsapp:|ms-|calculator:)/i;

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 850,
    minWidth: 900,
    minHeight: 650,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: "#f7f3f5",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  win.once("ready-to-show", () => win.show());

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (EXTERNAL_SCHEMES.test(url)) {
      shell.openExternal(url).catch(() => {});
    }
    return { action: "deny" };
  });

  win.webContents.on("will-navigate", (event, url) => {
    if (url.startsWith("file://")) return;
    event.preventDefault();
    if (EXTERNAL_SCHEMES.test(url)) {
      shell.openExternal(url).catch(() => {});
    }
  });

  win.loadFile(APP_URL);
}

app.whenReady().then(() => {
  app.setAppUserModelId("ru.moikontakty.desktop");
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
