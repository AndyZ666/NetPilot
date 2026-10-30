/* Observe devices sequentially; never insert device-provided HTML or commands. */
(() => {
  const panels = Array.from(document.querySelectorAll('.device-live'));
  let queue = Promise.resolve();

  async function refresh(panel, force) {
    const status = panel.querySelector('[data-live-status]');
    const protocols = panel.querySelector('[data-live-protocols]');
    const timestamp = panel.querySelector('[data-live-time]');
    const button = panel.querySelector('[data-live-refresh]');
    button.disabled = true;
    status.textContent = 'Refreshing live state…';
    try {
      const options = {credentials: 'same-origin', cache: 'no-store'};
      if (force) {
        options.method = 'POST';
        options.body = new URLSearchParams({csrf_token: panel.dataset.liveCsrf});
      }
      const response = await fetch(force ? panel.dataset.refreshUrl : panel.dataset.liveUrl, options);
      const result = await response.json();
      protocols.replaceChildren();
      if (!response.ok || result.status !== 'available') {
        status.textContent = result.message || result.error || 'Live status unavailable.';
      } else {
        status.textContent = 'Management SSH reachable. Configured protocols; operational neighbors and sessions not checked.';
        const configured = result.protocols.filter(protocol => protocol.configured === true);
        for (const protocol of configured) {
          const badge = document.createElement('span');
          badge.className = 'inventory-tag protocol-tag';
          badge.textContent = `${protocol.label} (configured)`;
          if (protocol.interfaces.length) badge.title = `Interface settings: ${protocol.interfaces.join(', ')}`;
          protocols.append(badge);
        }
        if (!configured.length) {
          const empty = document.createElement('span');
          empty.className = 'inventory-muted';
          empty.textContent = 'No routing protocols configured in the observed configuration.';
          protocols.append(empty);
        }
      }
      const success = result.last_success ? new Date(result.last_success) : null;
      timestamp.textContent = `Last successful refresh: ${success && !Number.isNaN(success.getTime()) ? success.toLocaleString() : 'not yet'}.`;
    } catch (_) {
      protocols.replaceChildren();
      status.textContent = 'Live status unavailable. Refresh again when the GUI is reachable.';
    } finally {
      button.disabled = false;
    }
  }

  for (const panel of panels) {
    const button = panel.querySelector('[data-live-refresh]');
    button.addEventListener('click', () => {
      button.disabled = true;
      queue = queue.then(() => refresh(panel, true));
    });
    queue = queue.then(() => refresh(panel, false));
  }
})();
