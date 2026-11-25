
// TALOS / LibreMobile OS Client Runtime
(function() {
  function updateClock() {
    const d = new Date();
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    const el = document.getElementById('clock');
    if (el) el.textContent = `${h}:${m}`;
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

  // Sovereign App Store Client Loader
  async function loadStoreIndex() {
    const listEl = document.getElementById('store-package-list');
    if (!listEl) return;
    try {
      const headers = {};
      const token = window.LRD_BRIDGE_TOKEN || localStorage.getItem('LRD_BRIDGE_TOKEN') || 'sovereign_dev_token';
      if (token) {
        headers['Authorization'] = 'Bearer ' + token;
        headers['X-LRD-Token'] = token;
      }
      const resp = await fetch('/api/store/index', { headers });
      if (!resp.ok) {
        throw new Error('HTTP ' + resp.status + ': ' + resp.statusText);
      }
      const data = await resp.json();
      const isSigned = data.signed !== false;
      const metaBar = document.getElementById('store-meta-bar');
      if (metaBar) {
        if (!isSigned) {
          metaBar.innerHTML = '<span class="meta-pill" style="background:var(--danger, #dc2626); color:#fff;">⚠️ Unsigned Index</span><span class="meta-pill">Scorer v1.0.0</span>';
        } else {
          metaBar.innerHTML = '<span class="meta-pill">Ed25519 Signed</span><span class="meta-pill">Scorer v1.0.0</span>';
        }
      }

      const pkgs = data.apps || data.packages || [];
      if (pkgs.length === 0) {
        listEl.innerHTML = '<div class="store-loading">No packages available in repository index.</div>';
        return;
      }

      let bannerHtml = '';
      if (!isSigned) {
        bannerHtml = '<div class="store-unsigned-banner" style="background:#dc2626; color:#ffffff; padding:12px; border-radius:6px; margin-bottom:16px; font-weight:bold;">⚠️ Store index is UNSIGNED. Operator must provision a release key per store/POLICY.md.</div>';
      }

      const itemsHtml = pkgs.map(pkg => {
        const score = pkg.privacy_score || {};
        const grade = score.grade || 'N/A';
        const total = score.total_score != null ? score.total_score : '--';
        const bd = score.breakdown || {};
        const trackerCount = bd.tracker_absence ? bd.tracker_absence.detected_count : 0;
        const repro = pkg.reproducible ? '✔ Reproducible' : (pkg.reproducible_waiver ? '⚖ Waiver' : '✖ Unverified');
        const reproClass = pkg.reproducible ? 'badge-repro' : (pkg.reproducible_waiver ? 'badge-waiver' : 'badge-tracker-warn');
        const egress = bd.egress_alignment ? bd.egress_alignment.mode : 'none';
        const gradeClass = 'badge-grade-' + grade.toLowerCase().replace('+', 'plus');
        const trackerClass = trackerCount === 0 ? 'badge-tracker' : 'badge-tracker-warn';
        const trackerText = trackerCount === 0 ? '✔ 0 Trackers' : ('⚠ ' + trackerCount + ' Trackers');

        const scoreBadge = (!isSigned)
          ? '<span class="badge" style="background:#f59e0b; color:#000;">Score: unverified</span>'
          : '<span class="badge ' + gradeClass + '">' + grade + ' (' + total + '/100)</span>';

        const installBtn = (!isSigned)
          ? '<button class="btn-store-install" disabled title="Install disabled until index is signed" style="opacity:0.5; cursor:not-allowed;">Install</button>'
          : '<button class="btn-store-install">Install</button>';

        return [
          '<div class="store-card" data-package-id="' + pkg.id + '">',
          '  <div class="store-card-header">',
          '    <div>',
          '      <div class="store-pkg-name">' + pkg.name + '</div>',
          '      <div class="store-pkg-id">' + pkg.id + ' • v' + (pkg.version_name || '') + '</div>',
          '    </div>',
          '    ' + scoreBadge,
          '  </div>',
          '  <div class="store-pkg-summary">' + (pkg.summary || '') + '</div>',
          '  <div class="store-badges">',
          '    <span class="badge ' + trackerClass + '">' + trackerText + '</span>',
          '    <span class="badge ' + reproClass + '">' + repro + '</span>',
          '    <span class="badge badge-egress">🛡️ ' + egress + '</span>',
          '    <span class="badge badge-egress">📜 ' + (pkg.license || 'FOSS') + '</span>',
          '  </div>',
          '  <div class="store-card-actions" style="margin-top:10px; display:flex; justify-content:flex-end;">',
          '    ' + installBtn,
          '  </div>',
          '</div>'
        ].join('\n');
      }).join('\n');

      listEl.innerHTML = bannerHtml + itemsHtml;
    } catch (err) {
      listEl.innerHTML = '<div class="store-loading" style="color:var(--danger)">Failed to load store index: ' + err.message + '</div>';
    }
  }

  const refreshBtn = document.getElementById('btn-refresh-store');
  if (refreshBtn) refreshBtn.addEventListener('click', loadStoreIndex);
  loadStoreIndex();
})();
