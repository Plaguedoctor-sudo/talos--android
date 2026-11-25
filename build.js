#!/usr/bin/env node
/**
 * build.js — Deterministic build compiler for LibreDroid Touch Web Shell.
 * Generates production-ready mobile assets in dist/.
 */

const fs = require('fs');
const path = require('path');

const DIST_DIR = path.join(__dirname, 'dist');
const ASSETS_DIR = path.join(DIST_DIR, 'assets');

fs.mkdirSync(ASSETS_DIR, { recursive: true });

const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
  <title>TALOS / LibreMobile OS</title>
  <link rel="stylesheet" href="assets/app.css">
  <link rel="manifest" href="manifest.json">
</head>
<body class="sovereign-mobile-os">
  <!-- System Status Bar -->
  <header id="status-bar" class="status-bar">
    <div class="status-left">
      <span class="carrier-badge" id="carrier">TALOS 5G-NR</span>
      <span class="signal-bars" id="signal">●●●●○</span>
    </div>
    <div class="status-center">
      <span class="clock" id="clock">00:00</span>
    </div>
    <div class="status-right">
      <span class="guard-pill active" title="ARGUS Trust Spine Active">ARGUS</span>
      <span class="battery-pct" id="battery">80%</span>
      <span class="battery-icon">⚡</span>
    </div>
  </header>

  <!-- Main Viewport -->
  <main id="viewport" class="viewport">
    <!-- Active Domain & Kill-switches -->
    <section class="quick-controls card">
      <div class="control-row">
        <button class="toggle-btn active" id="btn-kill-mic">🎤 Mic [LIVE]</button>
        <button class="toggle-btn active" id="btn-kill-cam">📷 Cam [LIVE]</button>
        <button class="toggle-btn active" id="btn-kill-net">🛡️ Tor [ON]</button>
        <button class="toggle-btn active" id="btn-power-guard">🔋 80% Cap</button>
        <button class="toggle-btn active" id="btn-toggle-wifi">📶 Wi-Fi [ON]</button>
        <button class="toggle-btn" id="btn-toggle-hotspot">📡 Hotspot [OFF]</button>
        <button class="toggle-btn active" id="btn-toggle-bt">ᛒ BT [ON]</button>
        <button class="toggle-btn active" id="btn-firewall-arm">🛡️ FW [ARMED]</button>
        <button class="toggle-btn active" id="btn-privacy-mac">🔒 MAC Alibi</button>
        <button class="toggle-btn" id="btn-panic-kill">🛑 Panic Cut</button>
      </div>
    </section>

    <!-- App Drawer Grid -->
    <section class="app-drawer">
      <div class="app-item" data-app="telephony">
        <div class="app-icon dialer-icon">📞</div>
        <div class="app-title">Dialer</div>
      </div>
      <div class="app-item" data-app="messages">
        <div class="app-icon sms-icon">💬</div>
        <div class="app-title">Messages</div>
      </div>
      <div class="app-item" data-app="wifi">
        <div class="app-icon wifi-icon">📶</div>
        <div class="app-title">Wi-Fi/AP</div>
      </div>
      <div class="app-item" data-app="bluetooth">
        <div class="app-icon bt-icon">ᛒ</div>
        <div class="app-title">Bluetooth</div>
      </div>
      <div class="app-item" data-app="firewall">
        <div class="app-icon fw-icon">🛡️</div>
        <div class="app-title">Firewall</div>
      </div>
      <div class="app-item" data-app="camera">
        <div class="app-icon cam-icon">📸</div>
        <div class="app-title">Camera</div>
      </div>
      <div class="app-item" data-app="terminal">
        <div class="app-icon term-icon">💻</div>
        <div class="app-title">Terminal</div>
      </div>
      <div class="app-item" data-app="waydroid">
        <div class="app-icon droid-icon">🤖</div>
        <div class="app-title">Android Box</div>
      </div>
      <div class="app-item" data-app="security">
        <div class="app-icon argus-icon">🔒</div>
        <div class="app-title">Security</div>
      </div>
    </section>

    <!-- Hardware & Telemetry Monitor -->
    <section class="telemetry-panel card">
      <h3>Sovereign Subsystem State</h3>
      <div class="telemetry-grid">
        <div class="tel-metric">
          <span class="tel-label">Radio Mode:</span>
          <span class="tel-val" id="tel-radio">VoLTE / VoNR Ready</span>
        </div>
        <div class="tel-metric">
          <span class="tel-label">Wi-Fi & Hotspot:</span>
          <span class="tel-val success" id="tel-wifi">WPA3 Station / AP Ready</span>
        </div>
        <div class="tel-metric">
          <span class="tel-label">Bluetooth Subsystem:</span>
          <span class="tel-val success" id="tel-bt">Privacy MAC Rotated</span>
        </div>
        <div class="tel-metric">
          <span class="tel-label">Egress Firewall:</span>
          <span class="tel-val success" id="tel-firewall">Deny-by-Default (VPN Enforced)</span>
        </div>
        <div class="tel-metric">
          <span class="tel-label">IIO Accelerometer:</span>
          <span class="tel-val" id="tel-sensors">Upright (0, -9.8, 0)</span>
        </div>
        <div class="tel-metric">
          <span class="tel-label">dm-verity Rootfs:</span>
          <span class="tel-val success" id="tel-verity">ENFORCED (Tier 2)</span>
        </div>
        <div class="tel-metric">
          <span class="tel-label">Trust Chain:</span>
          <span class="tel-val success" id="tel-argus">BLAKE3 Chained</span>
        </div>
      </div>
    </section>
  </main>

  <!-- Layer Shell Dock Marker for Wayland Compositor -->
  <div id="dock-marker" class="dock-marker">
    <div class="home-indicator"></div>
  </div>

  <script src="assets/app.js"></script>
</body>
</html>
`;

const cssContent = `
:root {
  --bg-color: #0b0f19;
  --card-bg: #151c2c;
  --text-main: #f0f4f8;
  --text-muted: #8b9bb4;
  --accent: #00e5ff;
  --success: #00e676;
  --warning: #ffd600;
  --danger: #ff1744;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
  user-select: none;
  -webkit-touch-callout: none;
}

body.sovereign-mobile-os {
  background-color: var(--bg-color);
  color: var(--text-main);
  font-family: system-ui, -apple-system, sans-serif;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.status-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 18px;
  background: rgba(11, 15, 25, 0.95);
  font-size: 14px;
  font-weight: 600;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.guard-pill {
  background: var(--accent);
  color: #000;
  font-size: 11px;
  padding: 2px 7px;
  border-radius: 12px;
  margin-right: 6px;
  font-weight: 700;
}

.viewport {
  flex: 1;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  overflow-y: auto;
}

.card {
  background: var(--card-bg);
  border-radius: 16px;
  padding: 16px;
  border: 1px solid rgba(255, 255, 255, 0.05);
}

.control-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}

.toggle-btn {
  background: #202b42;
  color: var(--text-main);
  border: 1px solid rgba(255, 255, 255, 0.1);
  padding: 10px 4px;
  border-radius: 10px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
}

.toggle-btn.active {
  background: #004d40;
  border-color: var(--success);
  color: #a7ffeb;
}

.app-drawer {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 18px;
  padding: 8px 0;
}

.app-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.app-icon {
  width: 64px;
  height: 64px;
  background: #1c263c;
  border-radius: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 30px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  border: 1px solid rgba(255,255,255,0.06);
}

.app-title {
  font-size: 13px;
  color: var(--text-main);
  font-weight: 500;
}

.telemetry-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-top: 10px;
  font-size: 13px;
}

.tel-label {
  color: var(--text-muted);
  display: block;
  font-size: 11px;
}

.tel-val.success {
  color: var(--success);
  font-weight: 600;
}

.dock-marker {
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.home-indicator {
  width: 140px;
  height: 5px;
  background: rgba(255, 255, 255, 0.4);
  border-radius: 3px;
}
`;

const jsContent = `
// TALOS / LibreMobile OS Client Runtime
(function() {
  function updateClock() {
    const d = new Date();
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    const el = document.getElementById('clock');
    if (el) el.textContent = \`\${h}:\${m}\`;
  }
  setInterval(updateClock, 1000);
  updateClock();

  // App Launcher event dispatch
  document.querySelectorAll('.app-item').forEach(item => {
    item.addEventListener('click', () => {
      const app = item.getAttribute('data-app');
      console.log('Dispatching sovereign app launcher:', app);
      fetch('/api/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app })
      }).catch(e => console.warn('App dispatch fallback:', e));
    });
  });

  // Killswitch toggles
  document.querySelectorAll('.toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      btn.classList.toggle('active');
    });
  });
})();
`;

const manifestContent = JSON.stringify({
  name: "TALOS / LibreMobile OS",
  short_name: "LibreMobile",
  start_url: "/",
  display: "standalone",
  background_color: "#0b0f19",
  theme_color: "#0b0f19",
  icons: [
    {
      src: "assets/icon.png",
      sizes: "192x192",
      type: "image/png"
    }
  ]
}, null, 2);

fs.writeFileSync(path.join(DIST_DIR, 'index.html'), htmlContent);
fs.writeFileSync(path.join(ASSETS_DIR, 'app.css'), cssContent);
fs.writeFileSync(path.join(ASSETS_DIR, 'app.js'), jsContent);
fs.writeFileSync(path.join(DIST_DIR, 'manifest.json'), manifestContent);

console.log('✔ LibreDroid Web Shell build complete -> dist/ staged successfully.');
