/* ============================================================
   Admin console
   Directory of every account, a live activity monitor, and the
   controls to suspend, restore, remove or export.
   ============================================================ */

(function () {
  'use strict';

  var UI = window.XadonUI;
  var Store = window.XadonStore;
  var html = UI.html;
  var raw = UI.raw;

  /* ---------- overview ---------- */

  function overview() {
    var users = Store.allUsers();
    var events = Store.activity();
    var active = users.filter(function (u) { return u.status === 'active'; }).length;
    var suspended = users.length - active;
    var today = events.filter(function (e) { return Date.now() - e.at < 86400000; }).length;
    var google = users.filter(function (u) { return u.provider === 'google'; }).length;
    var neverSignedIn = users.filter(function (u) { return !u.lastLogin; }).length;

    return {
      title: 'Admin overview',
      subtitle: 'Deployment at a glance',
      body: html`
        <div class="page-head">
          <div class="row">
            <div>
              <h1>Deployment overview</h1>
              <p>Every figure here is counted from records held in this browser's storage.</p>
            </div>
            <button class="btn" id="exportAll">Export everything</button>
          </div>
        </div>

        <div class="grid four">
          <div class="card">
            <p class="tiny">Accounts</p>
            <div class="readout"><b>${users.length}</b><span>total</span></div>
            <p class="tiny" style="margin-top:.5rem">${active} active · ${suspended} suspended</p>
          </div>
          <div class="card">
            <p class="tiny">Events today</p>
            <div class="readout"><b>${today}</b><span>logged</span></div>
            <p class="tiny" style="margin-top:.5rem">${events.length} in the retained log</p>
          </div>
          <div class="card">
            <p class="tiny">Google accounts</p>
            <div class="readout"><b>${google}</b><span>of ${users.length}</span></div>
            <p class="tiny" style="margin-top:.5rem">${users.length - google} use a password</p>
          </div>
          <div class="card">
            <p class="tiny">Never signed in</p>
            <div class="readout"><b>${neverSignedIn}</b><span>accounts</span></div>
            <p class="tiny" style="margin-top:.5rem">Created but never returned</p>
          </div>
        </div>

        <div class="grid wide-left" style="margin-top:1rem">
          <div class="card">
            <div class="card-head">
              <div><h2>Live activity</h2><p>Updates as people use the console</p></div>
              <span class="pill clear"><span class="lamp pulse"></span>monitoring</span>
            </div>
            <div class="rows" id="adminFeed"></div>
            <button class="btn btn-sm" data-go="/admin/activity" style="margin-top:.75rem">Open the full monitor</button>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Newest accounts</h2><p>Most recently created</p></div></div>
            <div class="rows">
              ${raw(users.slice().sort(function (a, b) { return b.createdAt - a.createdAt; }).slice(0, 5).map(function (u) {
                return html`
                  <div class="entry">
                    <span class="ico info">${UI.initials(u.name)}</span>
                    <div class="body"><b>${u.name}</b><small>${u.email}</small></div>
                    <time>${UI.timeAgo(u.createdAt)}</time>
                  </div>`;
              }).join('') || html`<div class="empty"><b>No accounts yet</b><p>The first person to sign up appears here.</p></div>`)}
            </div>
          </div>
        </div>`,

      mount: function (root, ctx) {
        function drawFeed() {
          var feed = root.querySelector('#adminFeed');
          if (!feed) return;
          var events2 = Store.activity().slice(0, 7);
          feed.innerHTML = events2.length ? events2.map(function (e, i) {
            return html`
              <div class="entry ${i === 0 ? 'new' : ''}">
                <span class="ico ${e.category === 'auth' ? 'clear' : e.category === 'admin' ? 'warn' : 'info'}">·</span>
                <div class="body"><b>${e.action}</b><small>${e.userName} · ${e.category}</small></div>
                <time>${UI.timeAgo(e.at)}</time>
              </div>`;
          }).join('') : html`<div class="empty"><b>Quiet so far</b><p>Actions appear here the moment anyone uses the console.</p></div>`;
        }

        drawFeed();
        ctx.onActivity(drawFeed);

        root.querySelector('#exportAll').addEventListener('click', function () {
          UI.download('xadon-export.json', JSON.stringify(Store.exportAll(), null, 2), 'application/json');
          UI.toast('Exported. Password hashes are excluded.', 'clear');
        });
      }
    };
  }

  /* ---------- users ---------- */

  function users() {
    return {
      title: 'Accounts',
      subtitle: 'Everyone registered on this deployment',
      body: html`
        <div class="page-head">
          <div class="row">
            <div>
              <h1>Accounts</h1>
              <p>Suspend an account to block sign-in immediately. Any open session ends on their next action.</p>
            </div>
            <div class="input-group" style="max-width:280px">
              <input class="input" id="userSearch" placeholder="Search name or email">
            </div>
          </div>
        </div>
        <div id="userTable"></div>`,

      mount: function (root, ctx) {
        var search = root.querySelector('#userSearch');

        function draw() {
          var term = (search.value || '').trim().toLowerCase();
          var list = Store.allUsers().filter(function (u) {
            return !term || u.name.toLowerCase().indexOf(term) !== -1 || u.email.indexOf(term) !== -1;
          });

          root.querySelector('#userTable').innerHTML = list.length ? html`
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Account</th><th>Method</th><th>Status</th>
                    <th>Sign-ins</th><th>Last seen</th><th>Events</th><th></th>
                  </tr>
                </thead>
                <tbody>
                  ${raw(list.map(function (u) {
                    var count = Store.activity({ userId: u.id }).length;
                    return html`
                      <tr>
                        <td>
                          <b>${u.name}</b>
                          <div class="mono dim" style="font-size:.7rem">${u.email}</div>
                        </td>
                        <td><span class="pill">${u.provider}</span></td>
                        <td><span class="pill ${u.status === 'active' ? 'clear' : 'alert'}">${u.status}</span></td>
                        <td class="mono">${u.loginCount || 0}</td>
                        <td class="mono nowrap">${u.lastLogin ? UI.timeAgo(u.lastLogin) : 'never'}</td>
                        <td class="mono">${count}</td>
                        <td>
                          <div class="table-actions">
                            <button class="btn btn-sm" data-view="${u.id}">View</button>
                            <button class="btn btn-sm" data-toggle="${u.id}">${u.status === 'active' ? 'Suspend' : 'Restore'}</button>
                            <button class="btn btn-sm btn-danger" data-del="${u.id}">Delete</button>
                          </div>
                        </td>
                      </tr>`;
                  }).join(''))}
                </tbody>
              </table>
            </div>` : html`
            <div class="card"><div class="empty">
              <b>${term ? 'No account matches that' : 'No accounts yet'}</b>
              <p>${term ? 'Try part of a name or email address.' : 'Accounts appear here as soon as someone signs up.'}</p>
            </div></div>`;

          wire();
        }

        function wire() {
          root.querySelectorAll('[data-view]').forEach(function (btn) {
            btn.addEventListener('click', function () { showUser(btn.getAttribute('data-view')); });
          });

          root.querySelectorAll('[data-toggle]').forEach(function (btn) {
            btn.addEventListener('click', function () {
              var id = btn.getAttribute('data-toggle');
              var u = Store.findById(id);
              var next = u.status === 'active' ? 'suspended' : 'active';
              Store.updateUser(id, { status: next });
              Store.logActivity('Set account to ' + next, 'admin', { account: u.email }, 'admin');
              UI.toast(u.name + ' is now ' + next + '.', next === 'active' ? 'clear' : 'warn');
              draw();
            });
          });

          root.querySelectorAll('[data-del]').forEach(function (btn) {
            btn.addEventListener('click', function () {
              var id = btn.getAttribute('data-del');
              var u = Store.findById(id);
              UI.confirmAction({
                title: 'Delete ' + u.name + '?',
                message: 'The account and every event logged against it are removed.',
                warning: 'There is no backup. If this person is mid-incident, suspend instead — that blocks access without destroying the record.',
                danger: true,
                confirmLabel: 'Delete the account'
              }).then(function (ok) {
                if (!ok) return;
                Store.deleteUser(id);
                Store.logActivity('Deleted an account', 'admin', { account: u.email }, 'admin');
                UI.toast('Account deleted.', 'clear');
                draw();
              });
            });
          });
        }

        function showUser(id) {
          var u = Store.findById(id);
          if (!u) return;
          var events = Store.activity({ userId: id });
          var session = Store.currentSession();
          var isCurrent = session && session.userId === id;

          UI.modal({
            title: u.name,
            body: html`
              <p class="dim small mono">${u.email}</p>

              <div class="grid two" style="margin-top:1rem;gap:.5rem">
                <div class="card" style="padding:.75rem"><p class="tiny">Sign-ins</p><div class="readout"><b>${u.loginCount || 0}</b></div></div>
                <div class="card" style="padding:.75rem"><p class="tiny">Logged events</p><div class="readout"><b>${events.length}</b></div></div>
              </div>

              <div class="setting" style="margin-top:1rem"><div class="body"><b>Created</b></div><span class="mono small">${UI.fullDate(u.createdAt)}</span></div>
              <div class="setting"><div class="body"><b>Last sign-in</b></div><span class="mono small">${u.lastLogin ? UI.fullDate(u.lastLogin) : 'never'}</span></div>
              <div class="setting"><div class="body"><b>Method</b></div><span class="pill">${u.provider}</span></div>
              <div class="setting"><div class="body"><b>Session on this browser</b></div><span class="pill ${isCurrent ? 'clear' : ''}">${isCurrent ? 'open' : 'none'}</span></div>
              ${raw(isCurrent ? html`<div class="setting"><div class="body"><b>Browser</b><small>${UI.browserName(session.agent)} on ${UI.platformName(session.agent)}</small></div></div>` : '')}

              <h3 style="margin-top:1.25rem">Recent activity</h3>
              <div class="rows" style="margin-top:.5rem">
                ${raw(events.slice(0, 12).map(function (e) {
                  return html`<div class="entry"><span class="ico info">·</span><div class="body"><b>${e.action}</b><small>${e.category}</small></div><time>${UI.timeAgo(e.at)}</time></div>`;
                }).join('') || html`<div class="empty"><b>No activity</b><p>This account has not done anything yet.</p></div>`)}
              </div>`
          });
        }

        search.addEventListener('input', draw);
        draw();
      }
    };
  }

  /* ---------- activity monitor ---------- */

  function monitor() {
    return {
      title: 'Activity monitor',
      subtitle: 'Everything, from everyone',
      body: html`
        <div class="page-head">
          <div class="row">
            <div>
              <h1>Activity monitor</h1>
              <p>The most recent 600 events are retained. Older ones are dropped so storage never fills up.</p>
            </div>
            <div style="display:flex;gap:.5rem;flex-wrap:wrap">
              <select class="input" id="catFilter" style="width:auto">
                <option value="">All categories</option>
                <option value="auth">Sign-in and out</option>
                <option value="scan">Scans</option>
                <option value="view">Page views</option>
                <option value="vault">Vault</option>
                <option value="incident">Incident</option>
                <option value="account">Account changes</option>
                <option value="admin">Admin</option>
                <option value="community">Community</option>
              </select>
              <button class="btn" id="dlCsv">CSV</button>
              <button class="btn btn-danger" id="clearLog">Clear log</button>
            </div>
          </div>
        </div>
        <div id="logTable"></div>`,

      mount: function (root, ctx) {
        var filter = root.querySelector('#catFilter');

        function draw() {
          var list = Store.activity(filter.value ? { category: filter.value } : null);
          root.querySelector('#logTable').innerHTML = list.length ? html`
            <div class="table-wrap" style="max-height:62vh">
              <table>
                <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Type</th><th>Detail</th></tr></thead>
                <tbody>
                  ${raw(list.slice(0, 250).map(function (e) {
                    return html`
                      <tr>
                        <td class="mono nowrap">${UI.fullDate(e.at)}</td>
                        <td>${e.userName}</td>
                        <td>${e.action}</td>
                        <td><span class="pill ${e.category === 'admin' ? 'warn' : e.category === 'auth' ? 'clear' : ''}">${e.category}</span></td>
                        <td class="mono dim">${Object.keys(e.meta).length ? JSON.stringify(e.meta) : '—'}</td>
                      </tr>`;
                  }).join(''))}
                </tbody>
              </table>
            </div>` : html`
            <div class="card"><div class="empty"><b>Nothing to show</b><p>No events match this filter yet.</p></div></div>`;
        }

        filter.addEventListener('change', draw);
        ctx.onActivity(draw);
        draw();

        root.querySelector('#dlCsv').addEventListener('click', function () {
          var rows = [['Timestamp', 'User', 'Action', 'Category', 'Detail', 'Path']].concat(
            Store.activity().map(function (e) {
              return [new Date(e.at).toISOString(), e.userName, e.action, e.category, JSON.stringify(e.meta), e.path];
            })
          );
          UI.download('xadon-activity.csv', UI.toCsv(rows), 'text/csv;charset=utf-8');
        });

        root.querySelector('#clearLog').addEventListener('click', function () {
          UI.confirmAction({
            title: 'Clear the activity log?',
            message: 'Every recorded event is deleted.',
            warning: 'If you are investigating something, export the CSV first. Once cleared there is no copy.',
            danger: true,
            confirmLabel: 'Clear it'
          }).then(function (ok) {
            if (!ok) return;
            Store.clearActivity();
            Store.logActivity('Cleared the activity log', 'admin', {}, 'admin');
            draw();
            UI.toast('Log cleared.', 'clear');
          });
        });
      }
    };
  }

  /* ---------- admin settings ---------- */

  function adminSettings() {
    var cfg = window.XADON_CONFIG;
    return {
      title: 'Admin settings',
      subtitle: 'Deployment configuration',
      body: html`
        <div class="page-head">
          <h1>Admin settings</h1>
          <p>What is configured on this deployment, and what still needs a server.</p>
        </div>

        <div class="grid two">
          <div class="card">
            <div class="card-head"><div><h2>Configuration</h2><p>From assets/js/config.js</p></div></div>
            <div class="setting"><div class="body"><b>Recovery email</b><small>Where admin reset codes are addressed</small></div><span class="mono small">${cfg.admin.recoveryEmail}</span></div>
            <div class="setting"><div class="body"><b>Google sign-in</b><small>${cfg.googleClientId ? 'Client ID configured' : 'No Client ID set'}</small></div><span class="pill ${cfg.googleClientId ? 'clear' : 'warn'}">${cfg.googleClientId ? 'on' : 'off'}</span></div>
            <div class="setting"><div class="body"><b>Breach lookup</b><small>Outbound request to the k-anonymity range API</small></div><span class="pill ${cfg.breachLookup ? 'clear' : ''}">${cfg.breachLookup ? 'on' : 'off'}</span></div>
            <div class="setting"><div class="body"><b>Version</b></div><span class="mono small">${cfg.version}</span></div>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Before you take real users</h2><p>In priority order</p></div></div>
            <div class="playbook">
              <div class="step"><div><b>Move authentication to a server</b><p>Accounts, hashes and sessions belong in a database behind an API. Everything in store.js maps one-to-one onto server endpoints.</p></div></div>
              <div class="step"><div><b>Verify the Google token server-side</b><p>Send the credential to your backend and check its signature against Google's public keys.</p></div></div>
              <div class="step"><div><b>Replace this admin gate</b><p>The credentials sit in client JavaScript. Anyone can read them. Put the admin console behind real server-side auth with its own role check.</p></div></div>
              <div class="step"><div><b>Connect a mail service</b><p>Resend, Postmark or SES in a serverless function, so reset codes actually send instead of opening a draft.</p></div></div>
              <div class="step"><div><b>Add security headers</b><p>A content security policy, HSTS and frame-ancestors are already stubbed in vercel.json.</p></div></div>
            </div>
          </div>

          <div class="card span-all">
            <div class="guardrail">
              <div>
                <b>The honest summary of this build</b>
                <p>
                  The security tools are real and work correctly — the link and message analysis,
                  the hashing, the breach lookup and the vault encryption all do what they claim.
                  The account system is a faithful reference implementation in the wrong place:
                  a browser cannot keep a secret, so treat it as the blueprint for the server
                  version rather than the finished article.
                </p>
              </div>
            </div>
          </div>
        </div>`,
      mount: function () {}
    };
  }

  window.XadonAdmin = {
    overview: overview,
    users: users,
    monitor: monitor,
    settings: adminSettings
  };
})();
