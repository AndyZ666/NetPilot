(() => {
  const panel = document.getElementById('ztp-progress');
  const retry = document.getElementById('ztp-retry');
  if (!panel || !retry) return;
  retry.addEventListener('submit', () => { retry.querySelector('button').disabled = true; });
  async function refresh() {
    try {
      const response = await fetch(panel.dataset.statusUrl, {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error();
      const job = await response.json();
      document.getElementById('ztp-state').textContent = job.state;
      document.getElementById('ztp-message').textContent = job.message;
      document.getElementById('ztp-ready').hidden = job.state !== 'Ready';
      retry.hidden = job.state !== 'Failed' && job.started;
      if (job.state === 'Ready' || job.state === 'Failed' || !job.started) return;
    } catch (_) {
      document.getElementById('ztp-message').textContent = 'Status temporarily unavailable. Refresh this page before retrying.';
    }
    window.setTimeout(refresh, 2000);
  }
  window.setTimeout(refresh, 2000);
})();
