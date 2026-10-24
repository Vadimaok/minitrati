const { app, BrowserWindow, shell, Menu } = require('electron');

const APP_URL = 'https://vadimaok.github.io/minitrati/';
const APP_HOST = 'vadimaok.github.io';
const DESKTOP_CSS = `
  @media (min-width: 900px) {
    body { padding: 22px 28px 38px !important; }
    .wrap { width: min(100%, 1320px) !important; max-width: 1320px !important; }
    .top { margin-bottom: 20px !important; }
    .hero { padding: 30px !important; border-radius: 26px !important; }
    .grid { grid-template-columns: minmax(0, 1.05fr) minmax(0, .95fr) !important; gap: 18px !important; margin-top: 18px !important; }
    .card { padding: 22px !important; border-radius: 24px !important; }
    .feature-grid { max-width: none !important; grid-template-columns: repeat(3, minmax(0, 1fr)) !important; gap: 18px !important; margin-top: 18px !important; }
    .feature-card { padding: 22px !important; }
    .panel { width: min(920px, calc(100vw - 80px)) !important; max-width: 920px !important; max-height: calc(100vh - 64px) !important; bottom: 32px !important; left: 50% !important; right: auto !important; transform: translateX(-50%) !important; border-radius: 26px !important; padding: 22px 26px !important; }
    .panel .grab { display: none !important; }
    .fab { right: 30px !important; bottom: 28px !important; }
    .toast { bottom: 28px !important; }
    .profilebar { margin-bottom: 20px !important; }
    button, input, select, textarea { font-size: 15px; }
    button { transition: transform .14s ease, filter .14s ease, border-color .14s ease; }
    button:hover { filter: brightness(1.08); }
    button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  }
`;

let mainWindow;
function openMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 960,
    minWidth: 1024,
    minHeight: 700,
    title: 'Provoda Staff',
    backgroundColor: '#0b0f14',
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.insertCSS(DESKTOP_CSS).catch(() => {});
  });
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    try {
      const parsed = new URL(url);
      if (parsed.hostname !== APP_HOST && parsed.protocol !== 'file:') {
        event.preventDefault();
        if (parsed.protocol === 'https:' || parsed.protocol === 'http:') shell.openExternal(url);
      }
    } catch { event.preventDefault(); }
  });
  mainWindow.loadURL(APP_URL);
  mainWindow.on('closed', () => { mainWindow = null; });
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  openMainWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) openMainWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
