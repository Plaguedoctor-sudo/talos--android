
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
})();
