/* ============================================================
   Router and shell
   Single mount point, history-based routing, one shell for the
   defender console and one for the admin console.

   v4 registered five routes for eleven sidebar links, so half
   the product silently fell through to the dashboard. Routes are
   now declared in one table and the navigation is generated from
   the same table, which makes that class of bug impossible.
   ============================================================ */

(function () {
  'use strict';

  var UI = window.XadonUI;
  var Store = window.XadonStore;
  var Engine = window.XadonEngine;
  var Pages = window.XadonPages;
  var Admin = window.XadonAdmin;
  var Auth = window.XadonAuth;
  var html = UI.html;
  var raw = UI.raw;

  var mount = document.getElementById('app');

  /* ---------- navigation table: the single source of truth ---------- */

  var CONSOLE_NAV = [
    { group: 'Monitor' },
    { path: '/console',            label: 'Overview',          icon: '◱', page: Pages.overview },
    { path: '/console/device',     label: 'Device posture',    icon: '◈', page: Pages.device },

    { group: 'Inspect' },
    { path: '/console/links',      label: 'Link inspector',    icon: '⌁', page: Pages.links },
    { path: '/console/messages',   label: 'Message inspector', icon: '✉', page: Pages.messages },
    { path: '/console/passwords',  label: 'Password check',    icon: '⚿', page: Pages.passwords },
    { path: '/console/files',      label: 'File fingerprint',  icon: '⊞', page: Pages.files },

    { group: 'Respond' },
    { path: '/console/incident',   label: 'Incident playbook', icon: '✚', page: Pages.incident, tag: '7' },
    { path: '/console/vault',      label: 'Vault',             icon: '⬢', page: Pages.vault },

    { group: 'Account' },
    { path: '/console/activity',   label: 'My activity',       icon: '≡', page: Pages.activity },
    { path: '/console/guide',      label: 'Guide',             icon: '?', page: Pages.guide },
    { path: '/community',          label: 'Community',         icon: '★', page: Pages.community },
    { path: '/console/settings',   label: 'Settings',          icon: '⚙', page: Pages.settings }
  ];

  var ADMIN_NAV = [
    { group: 'Administration' },
    { path: '/admin/overview', label: 'Overview',         icon: '◱', page: Admin.overview },
    { path: '/admin/users',    label: 'Accounts',         icon: '◉', page: Admin.users },
    { path: '/admin/activity', label: 'Activity monitor', icon: '≡', page: Admin.monitor },
    { path: '/admin/settings', label: 'Settings',         icon: '⚙', page: Admin.settings }
  ];

  function findRoute(table, path) {
    for (var i = 0; i < table.length; i++) {
      if (table[i].path === path) return table[i];
    }
    return null;
  }

  /* ---------- shared runtime state ---------- */

  var state = {
    signals: [],
    signalSubs: [],
    activitySubs: [],
    stripTimer: null
  };

  document.addEventListener('xadon:signal', function (e) {
    state.signals.unshift(e.detail);
    if (state.signals.length > 40) state.signals.length = 40;
    state.signalSubs.forEach(function (fn) { try { fn(e.detail); } catch (err) { console.warn(err); } });
    drawStrip();
  });

  document.addEventListener('xadon:activity', function (e) {
    state.activitySubs.forEach(function (fn) { try { fn(e.detail); } catch (err) { console.warn(err); } });
  });

  function resetSubscriptions() {
    state.signalSubs = [];
    state.activitySubs = [];
    if (state.stripTimer) { clearInterval(state.stripTimer); state.stripTimer = null; }
  }

  /* ---------- live signal strip ---------- */

  var battery = null;
  if (navigator.getBattery) {
    navigator.getBattery().then(function (b) { battery = b; }).catch(function () {});
  }

  function stripMarkup() {
    var online = navigator.onLine;
    var secure = window.isSecureContext;
    var conn = navigator.connection;
    var signalCount = state.signals.length;

    var cells = [
      { lamp: online ? '' : 'alert', label: 'network', value: online ? (conn && conn.effectiveType ? conn.effectiveType : 'online') : 'offline' },
      { lamp: secure ? '' : 'alert', label: 'channel', value: secure ? 'https' : 'insecure' },
      { lamp: 'amber', label: 'signals', value: String(signalCount) },
      { lamp: '', label: 'clock', value: UI.clock() }
    ];

    if (battery) {
      var pct = Math.round(battery.level * 100);
      cells.splice(3, 0, {
        lamp: pct <= 15 && !battery.charging ? 'alert' : '',
        label: 'battery',
        value: pct + '%' + (battery.charging ? ' ⚡' : '')
      });
    }

    return cells.map(function (c) {
      return html`<div><span class="lamp ${c.lamp} ${c.lamp === '' ? 'pulse' : ''}"></span>${c.label} <b>${c.value}</b></div>`;
    }).join('');
  }

  function drawStrip() {
    var strip = document.getElementById('strip');
    if (strip) strip.innerHTML = stripMarkup();
  }

  /* ---------- shells ---------- */

  function renderNav(table, currentPath) {
    return table.map(function (item) {
      if (item.group) return html`<div class="nav-group">${item.group}</div>`;
      return html`
        <button class="${currentPath === item.path ? 'active' : ''}" data-go="${item.path}">
          <span class="ico">${item.icon}</span>${item.label}
          ${raw(item.tag ? html`<span class="tag">${item.tag}</span>` : '')}
        </button>`;
    }).join('');
  }

  function renderShell(options) {
    mount.innerHTML = html`
      <div class="shell">
        <aside class="rail" id="rail">
          <div class="rail-head">
            <div class="brandmark">
              <span class="glyph">◈</span>
              <b>XADON</b><span>${options.mode === 'admin' ? 'Admin' : 'Defense'}</span>
            </div>
          </div>
          <nav class="nav">${raw(renderNav(options.nav, options.path))}</nav>
          <div class="rail-foot">
            ${raw(options.footer)}
          </div>
        </aside>

        <div class="main">
          <header class="topbar">
            <button class="btn btn-sm menu-btn" id="menuBtn" aria-label="Open navigation">☰</button>
            <h2>${options.title}</h2>
            <span class="spacer"></span>
            <span class="pill">${options.subtitle}</span>
          </header>
          <div class="strip" id="strip">${raw(stripMarkup())}</div>
          <main class="page" id="pageRoot">${raw(options.body)}</main>
          ${raw(UI.footer())}
        </div>
      </div>`;

    var rail = document.getElementById('rail');
    document.getElementById('menuBtn').addEventListener('click', function () {
      rail.classList.add('open');
      var scrim = document.createElement('div');
      scrim.className = 'scrim';
      scrim.addEventListener('click', function () {
        rail.classList.remove('open');
        scrim.remove();
      });
      document.body.appendChild(scrim);
    });

    UI.wireRoutes(mount, navigate);
    state.stripTimer = setInterval(drawStrip, 1000);
  }

  function consoleFooter(user) {
    return html`
      <button class="who" data-go="/console/settings">
        <span class="avatar">${UI.initials(user.name)}</span>
        <span><b>${user.name}</b><small>${user.email}</small></span>
      </button>
      <button class="btn btn-sm btn-block" id="signOutBtn" style="margin-top:.5rem">Sign out</button>`;
  }

  function adminFooter() {
    return html`
      <div class="who" style="cursor:default">
        <span class="avatar">AD</span>
        <span><b>Administrator</b><small>Operator session</small></span>
      </div>
      <button class="btn btn-sm btn-block" id="adminOutBtn" style="margin-top:.5rem">End admin session</button>`;
  }

  /* ---------- routing ---------- */

  function path() {
    var p = location.pathname.replace(/\/+$/, '');
    return p || '/';
  }

  function navigate(to) {
    if (to === path()) { render(); return; }
    history.pushState({}, '', to);
    render();
    window.scrollTo(0, 0);
  }

  window.addEventListener('popstate', render);

  function render() {
    resetSubscriptions();
    var p = path();
    var user = Store.currentUser();
    var isAdmin = Store.adminActive();

    /* --- admin area --- */
    if (p === '/admin') {
      if (isAdmin) { navigate('/admin/overview'); return; }
      Auth.adminScreen(navigate, mount);
      return;
    }

    if (p.indexOf('/admin/') === 0) {
      if (!isAdmin) {
        UI.toast('Sign in as administrator first.', 'warn');
        history.replaceState({}, '', '/admin');
        Auth.adminScreen(navigate, mount);
        return;
      }
      var adminRoute = findRoute(ADMIN_NAV, p) || findRoute(ADMIN_NAV, '/admin/overview');
      var adminCtx = {
        navigate: navigate,
        signals: state.signals,
        onSignal: function (fn) { state.signalSubs.push(fn); },
        onActivity: function (fn) { state.activitySubs.push(fn); }
      };
      var adminView = adminRoute.page(adminCtx);
      renderShell({
        mode: 'admin',
        nav: ADMIN_NAV,
        path: adminRoute.path,
        title: adminView.title,
        subtitle: adminView.subtitle,
        body: adminView.body,
        footer: adminFooter()
      });
      document.getElementById('adminOutBtn').addEventListener('click', function () {
        Store.adminSignOut();
        UI.toast('Admin session ended.', 'clear');
        navigate('/admin');
      });
      if (adminView.mount) adminView.mount(document.getElementById('pageRoot'), adminCtx);
      return;
    }

    /* --- auth screens --- */
    if (p === '/signin' || p === '/signup' || p === '/login') {
      if (user) { navigate('/console'); return; }
      Auth.authScreen(p === '/signup' ? 'signup' : 'signin', navigate, mount);
      return;
    }

    /* --- community is readable without an account --- */
    if (p === '/community' && !user) {
      var publicView = Pages.community();
      mount.innerHTML = html`
        <div class="auth">
          <div style="max-width:1080px;width:100%;margin:0 auto;padding:2rem 1.5rem;flex:1">
            <div class="brandmark" style="margin-bottom:2rem">
              <span class="glyph">◈</span><b>XADON</b><span>Phone Defense</span>
            </div>
            ${raw(publicView.body)}
            <button class="btn btn-primary" data-go="/signup" style="margin-top:1.5rem">Create an account</button>
          </div>
          ${raw(UI.footer())}
        </div>`;
      UI.wireRoutes(mount, navigate);
      publicView.mount(mount);
      return;
    }

    /* --- everything else needs an account --- */
    if (!user) {
      history.replaceState({}, '', '/signin');
      Auth.authScreen('signin', navigate, mount);
      return;
    }

    Store.touchSession();
    Engine.startTelemetry();

    var route = findRoute(CONSOLE_NAV, p);
    if (!route) {
      /* Unknown path: say so rather than silently showing the dashboard. */
      renderShell({
        mode: 'console',
        nav: CONSOLE_NAV,
        path: '/console',
        title: 'Not found',
        subtitle: 'no such page',
        body: html`
          <div class="card">
            <div class="empty">
              <b>There is nothing at ${p}</b>
              <p>The link may be out of date. Everything available is listed in the sidebar.</p>
              <button class="btn btn-primary" data-go="/console" style="margin-top:1rem">Back to the overview</button>
            </div>
          </div>`,
        footer: consoleFooter(user)
      });
      bindConsoleFooter();
      return;
    }

    var ctx = {
      user: user,
      navigate: navigate,
      signals: state.signals,
      onSignal: function (fn) { state.signalSubs.push(fn); },
      onActivity: function (fn) { state.activitySubs.push(fn); }
    };

    var view = route.page(ctx);
    renderShell({
      mode: 'console',
      nav: CONSOLE_NAV,
      path: route.path,
      title: view.title,
      subtitle: view.subtitle,
      body: view.body,
      footer: consoleFooter(user)
    });
    bindConsoleFooter();
    if (view.mount) view.mount(document.getElementById('pageRoot'), ctx);
  }

  function bindConsoleFooter() {
    var btn = document.getElementById('signOutBtn');
    if (!btn) return;
    btn.addEventListener('click', function () {
      Store.endSession();
      navigate('/signin');
      UI.toast('Signed out.', 'clear');
    });
  }

  /* ---------- keyboard shortcuts ---------- */

  document.addEventListener('keydown', function (e) {
    if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== 'k') return;
    if (!Store.currentUser()) return;
    e.preventDefault();

    var items = CONSOLE_NAV.filter(function (i) { return i.path; });
    UI.modal({
      title: 'Jump to',
      body: html`
        <input class="input" id="paletteInput" placeholder="Type to filter…" autocomplete="off">
        <div class="rows" id="paletteList" style="margin-top:.75rem;max-height:46vh;overflow:auto"></div>`,
      onOpen: function (box) {
        var input = box.querySelector('#paletteInput');
        var list = box.querySelector('#paletteList');

        function draw() {
          var term = input.value.toLowerCase();
          var matches = items.filter(function (i) { return i.label.toLowerCase().indexOf(term) !== -1; });
          list.innerHTML = matches.length ? matches.map(function (i) {
            return html`<button class="entry" data-jump="${i.path}" style="width:100%;text-align:left;cursor:pointer">
              <span class="ico info">${i.icon}</span>
              <div class="body"><b>${i.label}</b><small class="mono">${i.path}</small></div>
            </button>`;
          }).join('') : html`<div class="empty"><b>No match</b><p>Try part of the page name.</p></div>`;

          list.querySelectorAll('[data-jump]').forEach(function (btn) {
            btn.addEventListener('click', function () {
              UI.closeModal();
              navigate(btn.getAttribute('data-jump'));
            });
          });
        }

        input.addEventListener('input', draw);
        input.addEventListener('keydown', function (ev) {
          if (ev.key !== 'Enter') return;
          var first = list.querySelector('[data-jump]');
          if (first) first.click();
        });
        draw();
        input.focus();
      }
    });
  });

  /* ---------- boot ---------- */

  if (path() === '/') {
    history.replaceState({}, '', Store.currentUser() ? '/console' : '/signin');
  }

  render();

  window.addEventListener('beforeunload', function () {
    Engine.stopTelemetry();
    if (state.stripTimer) clearInterval(state.stripTimer);
  });
})();
