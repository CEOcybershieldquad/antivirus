/* ============================================================
   UI helpers
   Escaping, toasts, modals, formatting, shared chrome.

   Every value that reaches innerHTML goes through esc() first.
   The v4 build escaped some values and not others, which meant a
   display name containing markup could inject into the audit log
   and the event stream. One helper, used everywhere, removes the
   chance of forgetting.
   ============================================================ */

(function () {
  'use strict';

  var ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  function esc(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[&<>"']/g, function (ch) { return ENTITIES[ch]; });
  }

  /* Escaping tagged template: html`<b>${userInput}</b>` */
  function html(strings) {
    var values = Array.prototype.slice.call(arguments, 1);
    return strings.reduce(function (acc, part, i) {
      var v = values[i - 1];
      if (Array.isArray(v)) v = v.join('');
      else if (v && v.__raw) v = v.value;
      else v = esc(v);
      return acc + v + part;
    });
  }

  function raw(value) { return { __raw: true, value: value }; }

  /* ---------- formatting ---------- */

  function timeAgo(ts) {
    var diff = Math.floor((Date.now() - ts) / 1000);
    if (diff < 10) return 'just now';
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    return new Date(ts).toLocaleDateString();
  }

  function clock(ts) {
    return new Date(ts || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function fullDate(ts) {
    if (!ts) return '—';
    return new Date(ts).toLocaleString([], {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit'
    });
  }

  function bytes(n) {
    if (!n && n !== 0) return '—';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    var v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + ' ' + units[i];
  }

  function initials(name) {
    return String(name || '?')
      .trim()
      .split(/\s+/)
      .slice(0, 2)
      .map(function (p) { return p.charAt(0); })
      .join('')
      .toUpperCase() || '?';
  }

  function browserName(ua) {
    var s = String(ua || '');
    if (/edg\//i.test(s)) return 'Edge';
    if (/opr\//i.test(s)) return 'Opera';
    if (/chrome\//i.test(s) && !/chromium/i.test(s)) return 'Chrome';
    if (/firefox\//i.test(s)) return 'Firefox';
    if (/safari\//i.test(s)) return 'Safari';
    return 'Unknown browser';
  }

  function platformName(ua) {
    var s = String(ua || '');
    if (/android/i.test(s)) return 'Android';
    if (/iphone|ipad|ipod/i.test(s)) return 'iOS';
    if (/windows/i.test(s)) return 'Windows';
    if (/mac os x/i.test(s)) return 'macOS';
    if (/linux/i.test(s)) return 'Linux';
    return 'Unknown platform';
  }

  /* ---------- toasts ---------- */

  function tray() {
    var el = document.querySelector('.toast-tray');
    if (!el) {
      el = document.createElement('div');
      el.className = 'toast-tray';
      el.setAttribute('role', 'status');
      el.setAttribute('aria-live', 'polite');
      document.body.appendChild(el);
    }
    return el;
  }

  function toast(message, tone) {
    var el = document.createElement('div');
    el.className = 'toast ' + (tone || '');
    el.innerHTML = html`<span class="lamp ${tone === 'alert' ? 'alert' : tone === 'warn' ? 'amber' : ''}"></span><span>${message}</span>`;
    tray().appendChild(el);
    setTimeout(function () {
      el.style.opacity = '0';
      el.style.transition = 'opacity .25s';
      setTimeout(function () { el.remove(); }, 260);
    }, 4200);
    return el;
  }

  /* ---------- modal ---------- */

  var lastFocus = null;

  function modal(options) {
    close();
    lastFocus = document.activeElement;

    var backdrop = document.createElement('div');
    backdrop.className = 'backdrop';
    backdrop.innerHTML = html`
      <div class="modal" role="dialog" aria-modal="true" aria-label="${options.title || 'Dialog'}">
        <button class="modal-close" aria-label="Close">×</button>
        <h2>${options.title || ''}</h2>
        ${raw(options.body || '')}
      </div>`;
    document.body.appendChild(backdrop);

    backdrop.querySelector('.modal-close').addEventListener('click', close);
    backdrop.addEventListener('mousedown', function (e) { if (e.target === backdrop) close(); });

    document.addEventListener('keydown', onKey);

    /* keep tab focus inside the dialog */
    var focusable = backdrop.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    if (focusable.length) focusable[focusable.length > 1 ? 1 : 0].focus();

    backdrop.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab' || !focusable.length) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });

    if (typeof options.onOpen === 'function') options.onOpen(backdrop);
    return backdrop;
  }

  function onKey(e) { if (e.key === 'Escape') close(); }

  function close() {
    var existing = document.querySelector('.backdrop');
    if (existing) existing.remove();
    document.removeEventListener('keydown', onKey);
    if (lastFocus && lastFocus.focus) { lastFocus.focus(); lastFocus = null; }
  }

  function confirmAction(options) {
    return new Promise(function (resolve) {
      var box = modal({
        title: options.title,
        body: html`
          <p class="dim small">${options.message}</p>
          ${raw(options.warning ? html`<div class="guardrail" style="margin-top:1rem"><div><b>${options.warningTitle || 'Before you continue'}</b><p>${options.warning}</p></div></div>` : '')}
          <div class="modal-actions">
            <button class="btn" data-act="cancel">${options.cancelLabel || 'Cancel'}</button>
            <button class="btn ${options.danger ? 'btn-danger' : 'btn-primary'}" data-act="ok">${options.confirmLabel || 'Continue'}</button>
          </div>`
      });
      box.querySelector('[data-act="cancel"]').addEventListener('click', function () { close(); resolve(false); });
      box.querySelector('[data-act="ok"]').addEventListener('click', function () { close(); resolve(true); });
    });
  }

  /* ---------- download ---------- */

  function download(filename, content, mime) {
    var blob = new Blob([content], { type: mime || 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    /* Revoke on the next tick — revoking synchronously can cancel
       the download in some browsers. This was a bug in v4. */
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }

  function toCsv(rows) {
    return rows.map(function (row) {
      return row.map(function (cell) {
        var value = cell === null || cell === undefined ? '' : String(cell);
        return /[",\n]/.test(value) ? '"' + value.replace(/"/g, '""') + '"' : value;
      }).join(',');
    }).join('\r\n');
  }

  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text)
        .then(function () { toast('Copied to clipboard.', 'clear'); })
        .catch(function () { toast('Could not copy. Select the text and copy manually.', 'warn'); });
    }
    toast('Clipboard needs a secure (https) connection. Select the text and copy manually.', 'warn');
    return Promise.resolve();
  }

  /* ---------- shared chrome ---------- */

  function footer() {
    var cfg = window.XADON_CONFIG;
    return html`
      <footer class="site-foot">
        <div class="site-foot-inner">
          <div>
            Built by <b>${cfg.creator}</b> · ${cfg.product} v${cfg.version}
            <div class="tiny" style="margin-top:.25rem">
              Defensive tooling. It analyses what you paste in and what this browser reports — it does not reach into other people's devices.
            </div>
          </div>
          <div class="links">
            <a href="https://github.com/${cfg.githubUser}" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="mailto:${cfg.supportEmail}">${cfg.supportEmail}</a>
            <button class="btn btn-sm star-btn" data-go="/community">
              ${raw(starIcon())} Star the repos
            </button>
          </div>
        </div>
      </footer>`;
  }

  function starIcon() {
    return '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">' +
      '<path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.75.75 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Z"/></svg>';
  }

  function googleIcon() {
    return '<svg viewBox="0 0 24 24" aria-hidden="true">' +
      '<path fill="#4285F4" d="M23.5 12.27c0-.79-.07-1.54-.2-2.27H12v4.51h6.47a5.54 5.54 0 0 1-2.4 3.63v3h3.87c2.27-2.09 3.56-5.17 3.56-8.87Z"/>' +
      '<path fill="#34A853" d="M12 24c3.24 0 5.96-1.08 7.94-2.91l-3.87-3c-1.08.72-2.45 1.16-4.07 1.16-3.13 0-5.78-2.11-6.73-4.96H1.29v3.09A12 12 0 0 0 12 24Z"/>' +
      '<path fill="#FBBC05" d="M5.27 14.29a7.2 7.2 0 0 1 0-4.58V6.62H1.29a12 12 0 0 0 0 10.76l3.98-3.09Z"/>' +
      '<path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.43-3.43C17.95 1.19 15.23 0 12 0A12 12 0 0 0 1.29 6.62l3.98 3.09C6.22 6.86 8.87 4.75 12 4.75Z"/></svg>';
  }

  /* Attaches click handlers for every [data-go] route button in a container */
  function wireRoutes(root, navigate) {
    (root || document).querySelectorAll('[data-go]').forEach(function (el) {
      el.addEventListener('click', function (e) {
        e.preventDefault();
        navigate(el.getAttribute('data-go'));
      });
    });
  }

  window.XadonUI = {
    esc: esc,
    html: html,
    raw: raw,
    timeAgo: timeAgo,
    clock: clock,
    fullDate: fullDate,
    bytes: bytes,
    initials: initials,
    browserName: browserName,
    platformName: platformName,
    toast: toast,
    modal: modal,
    closeModal: close,
    confirmAction: confirmAction,
    download: download,
    toCsv: toCsv,
    copy: copy,
    footer: footer,
    starIcon: starIcon,
    googleIcon: googleIcon,
    wireRoutes: wireRoutes
  };
})();
