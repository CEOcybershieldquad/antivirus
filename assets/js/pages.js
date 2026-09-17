/* ============================================================
   Console pages
   Each page returns { title, subtitle, body, mount(root) }.
   The router in app.js renders the shell and calls mount().
   ============================================================ */

(function () {
  'use strict';

  var UI = window.XadonUI;
  var Store = window.XadonStore;
  var Engine = window.XadonEngine;
  var html = UI.html;
  var raw = UI.raw;

  /* ---------- shared fragments ---------- */

  function howto(summary, steps) {
    return html`
      <details class="howto">
        <summary>${summary}</summary>
        <div class="howto-body">
          <ol>${raw(steps.map(function (s) { return html`<li>${raw(s)}</li>`; }).join(''))}</ol>
        </div>
      </details>`;
  }

  function verdictBlock(result, kind) {
    var labels = {
      clear: { title: 'Nothing alarming found', sigil: '✓' },
      caution: { title: 'Treat this with caution', sigil: '!' },
      high: { title: 'Strong signs of an attack', sigil: '✕' },
      unreadable: { title: 'Could not read that', sigil: '?' }
    };
    var meta = labels[result.verdict] || labels.caution;

    var summaryLine = {
      clear: 'None of the known warning patterns matched. Stay alert anyway — absence of evidence is not proof of safety.',
      caution: 'Some patterns matched. Verify through a channel you started yourself before you act on it.',
      high: 'Multiple patterns matched that rarely appear together by accident. Do not enter anything here.',
      unreadable: 'Nothing here parsed as valid input.'
    }[result.verdict];

    var findings = result.findings.map(function (f) {
      return html`<div class="finding ${f.severity}"><div><b>${f.title}</b><p>${f.detail}</p></div></div>`;
    }).join('');

    var parts = result.parts ? html`
      <div class="breakdown">
        <div><small>Scheme</small><b>${result.parts.scheme}</b></div>
        <div><small>Host</small><b>${result.parts.host}</b></div>
        <div><small>Registered domain</small><b>${result.parts.domain}</b></div>
        <div><small>Path</small><b>${result.parts.path}</b></div>
        <div><small>Query</small><b>${result.parts.query}</b></div>
      </div>` : '';

    return html`
      <div class="verdict ${result.verdict}">
        <div class="verdict-head">
          <span class="sigil">${meta.sigil}</span>
          <div><h3>${meta.title}</h3><p>${summaryLine}</p></div>
          <div class="readout"><b>${result.score}</b><span>/100 risk</span></div>
        </div>
        <div class="findings">${raw(findings)}</div>
        ${raw(parts)}
      </div>`;
  }

  /* =========================================================
     Overview
     ========================================================= */

  function overview(ctx) {
    var user = ctx.user;
    var checks = Engine.devicePosture();
    var score = Engine.postureScore(checks);
    var tone = score >= 85 ? '' : score >= 60 ? 'caution' : 'alert';
    var failing = checks.filter(function (c) { return c.state === 'fail' || c.state === 'warn'; });

    return {
      title: 'Overview',
      subtitle: 'Live posture and signals',
      body: html`
        <div class="page-head">
          <div class="row">
            <div>
              <h1>Hello, ${user.name.split(' ')[0]}.</h1>
              <p>
                This score comes from checks this browser can actually answer right now.
                It is recalculated on every visit, not stored and replayed.
              </p>
            </div>
            <button class="btn btn-primary" id="recheck">Run the checks again</button>
          </div>
        </div>

        <div class="grid wide-left">
          <div class="card">
            <div class="gauge-row">
              <div class="gauge ${tone}" style="--v:${score}">
                <div><b>${score}</b><small>posture</small></div>
              </div>
              <div style="flex:1;min-width:200px">
                <h2>${score >= 85 ? 'Solid setup' : score >= 60 ? 'A few things to fix' : 'Needs attention'}</h2>
                <p class="dim small" style="margin-top:.4rem">
                  ${failing.length
                    ? failing.length + ' of ' + checks.length + ' checks want your attention. Each one explains the fix.'
                    : 'Every weighted check passed on this browser and connection.'}
                </p>
                <button class="btn btn-sm" data-go="/console/device" style="margin-top:.85rem">See every check</button>
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-head">
              <div><h2>Live signals</h2><p>Real browser events, not a demo ticker</p></div>
              <span class="pill clear" id="liveLamp"><span class="lamp pulse"></span>listening</span>
            </div>
            <div class="rows" id="signalFeed"></div>
          </div>

          <div class="card span-all">
            <div class="card-head">
              <div><h2>Start here</h2><p>The four things worth doing in your first five minutes</p></div>
            </div>
            <div class="grid four">
              <button class="btn" data-go="/console/links" style="flex-direction:column;align-items:flex-start;padding:1rem;height:100%">
                <b>Inspect a link</b>
                <span class="tiny" style="text-align:left">Paste anything you were sent and see why it is or is not safe.</span>
              </button>
              <button class="btn" data-go="/console/messages" style="flex-direction:column;align-items:flex-start;padding:1rem;height:100%">
                <b>Inspect a message</b>
                <span class="tiny" style="text-align:left">Check an SMS or WhatsApp against known fraud patterns.</span>
              </button>
              <button class="btn" data-go="/console/passwords" style="flex-direction:column;align-items:flex-start;padding:1rem;height:100%">
                <b>Check a password</b>
                <span class="tiny" style="text-align:left">See if it appears in a known breach, without sending it anywhere.</span>
              </button>
              <button class="btn" data-go="/console/incident" style="flex-direction:column;align-items:flex-start;padding:1rem;height:100%">
                <b>Lost your phone</b>
                <span class="tiny" style="text-align:left">Work the playbook in order. The first hour matters most.</span>
              </button>
            </div>
          </div>
        </div>`,

      mount: function (root, ctx) {
        renderSignals(ctx);
        root.querySelector('#recheck').addEventListener('click', function () {
          Store.logActivity('Ran posture checks', 'scan');
          ctx.navigate('/console');
          UI.toast('Checks re-run against the current browser state.', 'clear');
        });
        ctx.onSignal(function () { renderSignals(ctx); });
      }
    };
  }

  function renderSignals(ctx) {
    var feed = document.getElementById('signalFeed');
    if (!feed) return;
    if (!ctx.signals.length) {
      feed.innerHTML = html`
        <div class="empty">
          <b>Nothing has happened yet</b>
          <p>Signals appear when something actually changes — the network drops, a permission is granted, the battery gets low. Try switching Wi-Fi off and on.</p>
        </div>`;
      return;
    }
    feed.innerHTML = ctx.signals.slice(0, 6).map(function (s, i) {
      var icon = s.tone === 'alert' ? '✕' : s.tone === 'warn' ? '!' : s.tone === 'clear' ? '✓' : '·';
      return html`
        <div class="entry ${i === 0 ? 'new' : ''}">
          <span class="ico ${s.tone}">${icon}</span>
          <div class="body"><b>${s.title}</b><small>${s.detail}</small></div>
          <time>${UI.timeAgo(s.at)}</time>
        </div>`;
    }).join('');
  }

  /* =========================================================
     Link inspector
     ========================================================= */

  function links() {
    return {
      title: 'Link inspector',
      subtitle: 'Check a web address before you open it',
      body: html`
        <div class="page-head">
          <h1>Link inspector</h1>
          <p>Paste any address. The checks run on this device — nothing is sent anywhere.</p>
        </div>

        ${raw(howto('How to use this', [
          'Long-press the link in WhatsApp, SMS or email and choose <b>Copy link</b>. Do not tap it.',
          'Paste it into the box and select <b>Inspect link</b>.',
          'Read the findings top to bottom. Red dots are the ones that matter.',
          'If anything is flagged, go to the service yourself — type the address or use the official app — instead of using the link.'
        ]))}

        <div class="card">
          <div class="field">
            <label for="urlIn">Address to inspect</label>
            <div class="input-group">
              <input class="input mono" id="urlIn" placeholder="https://example.com/login" spellcheck="false" autocapitalize="off">
              <button class="btn btn-primary" id="urlGo">Inspect link</button>
            </div>
            <div class="hint">Try one of these to see it work:
              <button class="btn-ghost btn-sm" data-sample="http://gtbank.secure-verify-account.tk/login?redirect=https%3a%2f%2fexample.com" style="padding:0;text-decoration:underline">a phishing pattern</button> ·
              <button class="btn-ghost btn-sm" data-sample="https://www.wikipedia.org/wiki/Phishing" style="padding:0;text-decoration:underline">a normal link</button>
            </div>
          </div>
          <div id="urlOut"></div>
        </div>`,

      mount: function (root) {
        var input = root.querySelector('#urlIn');
        var out = root.querySelector('#urlOut');

        function run() {
          var result = Engine.analyzeUrl(input.value);
          if (!result.ok) { UI.toast(result.error, 'warn'); return; }
          out.innerHTML = verdictBlock(result, 'link');
          Store.logActivity('Inspected a link', 'scan', {
            host: result.parts ? result.parts.host : 'unparsed',
            verdict: result.verdict,
            score: result.score
          });
        }

        root.querySelector('#urlGo').addEventListener('click', run);
        input.addEventListener('keydown', function (e) { if (e.key === 'Enter') run(); });
        root.querySelectorAll('[data-sample]').forEach(function (btn) {
          btn.addEventListener('click', function () {
            input.value = btn.getAttribute('data-sample');
            run();
          });
        });
        input.focus();
      }
    };
  }

  /* =========================================================
     Message inspector
     ========================================================= */

  function messages() {
    return {
      title: 'Message inspector',
      subtitle: 'Check a text, email or WhatsApp message',
      body: html`
        <div class="page-head">
          <h1>Message inspector</h1>
          <p>Fourteen fraud patterns, plus a full link inspection on any address inside the message.</p>
        </div>

        ${raw(howto('How to use this', [
          'Copy the whole message, including any link. Context changes the result.',
          'Paste it below and select <b>Inspect message</b>.',
          'Each match explains the tactic being used on you, not just that something matched.',
          'When money, codes or account access are involved, verify by calling a number you already had — never one from the message.'
        ]))}

        <div class="card">
          <div class="field">
            <label for="msgIn">Message text</label>
            <textarea class="input" id="msgIn" placeholder="Paste the full message here…"></textarea>
            <div class="hint">
              <button class="btn-ghost btn-sm" id="msgSample" style="padding:0;text-decoration:underline">Load an example scam</button>
            </div>
          </div>
          <button class="btn btn-primary" id="msgGo">Inspect message</button>
          <div id="msgOut"></div>
        </div>`,

      mount: function (root) {
        var input = root.querySelector('#msgIn');
        var out = root.querySelector('#msgOut');

        root.querySelector('#msgSample').addEventListener('click', function () {
          input.value = 'Dear Customer, your account has been SUSPENDED due to unusual activity. '
            + 'Kindly click the link below within 2 hours to verify your BVN and reactivate: '
            + 'http://gtbank-verify.secure-login.tk/update '
            + 'Failure to do so will lead to permanent closure. Do not share this message with anyone.';
        });

        root.querySelector('#msgGo').addEventListener('click', function () {
          var result = Engine.analyzeMessage(input.value);
          if (!result.ok) { UI.toast(result.error, 'warn'); return; }

          var linkSection = result.links.length
            ? html`<div class="card" style="margin-top:1rem"><div class="card-head"><div><h2>Links found in the message</h2><p>Each one inspected in full</p></div></div>${raw(result.links.map(function (r) { return verdictBlock(r, 'link'); }).join(''))}</div>`
            : '';

          out.innerHTML = verdictBlock(result, 'message') + linkSection;
          Store.logActivity('Inspected a message', 'scan', {
            verdict: result.verdict, score: result.score, links: result.links.length
          });
        });
      }
    };
  }

  /* =========================================================
     Password checker
     ========================================================= */

  function passwords() {
    return {
      title: 'Password check',
      subtitle: 'Strength, breach exposure and a generator',
      body: html`
        <div class="page-head">
          <h1>Password check</h1>
          <p>
            The breach lookup uses k-anonymity: only the first five characters of the
            password's SHA-1 hash leave this device, and the service returns hundreds of
            candidates. Your password cannot be reconstructed from that.
          </p>
        </div>

        ${raw(howto('How to use this', [
          'Type or paste the password you want to test. It is never stored and never sent.',
          'Read the strength reading first — it shows which patterns weaken it.',
          'Select <b>Check against breaches</b> to see whether it appears in known leaked datasets.',
          'If it appears even once, change it everywhere you used it. Attackers try breached passwords first.'
        ]))}

        <div class="grid two">
          <div class="card">
            <div class="card-head"><div><h2>Test a password</h2><p>Nothing is saved</p></div></div>
            <div class="field">
              <input class="input" id="pwIn" type="password" placeholder="Type a password" autocomplete="off">
              <div class="strength-meter" id="pwMeter"><i></i><i></i><i></i><i></i></div>
              <div class="hint">
                <label style="display:inline-flex;gap:.4rem;align-items:center;cursor:pointer">
                  <input type="checkbox" id="pwShow"> Show characters
                </label>
              </div>
            </div>
            <div id="pwReport"></div>
            <button class="btn btn-primary btn-block" id="pwBreach" style="margin-top:.75rem">Check against breaches</button>
            <div id="pwBreachOut"></div>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Generate a new one</h2><p>Uses the browser's cryptographic random source</p></div></div>
            <div class="field">
              <label for="genOut">Generated</label>
              <input class="input mono" id="genOut" readonly>
            </div>
            <div class="grid two" style="gap:.5rem">
              <button class="btn" id="genPhrase">Passphrase</button>
              <button class="btn" id="genRandom">Random string</button>
            </div>
            <button class="btn btn-primary btn-block" id="genCopy" style="margin-top:.5rem">Copy</button>
            <div class="guardrail" style="margin-top:1rem">
              <div>
                <b>Put it in a password manager</b>
                <p>A generated password you cannot remember is only useful if something else remembers it. Bitwarden, 1Password and the manager built into your browser all work.</p>
              </div>
            </div>
          </div>
        </div>`,

      mount: function (root) {
        var input = root.querySelector('#pwIn');
        var report = root.querySelector('#pwReport');
        var genOut = root.querySelector('#genOut');

        root.querySelector('#pwShow').addEventListener('change', function (e) {
          input.type = e.target.checked ? 'text' : 'password';
        });

        input.addEventListener('input', function () {
          var result = Engine.scorePassword(input.value);
          root.querySelectorAll('#pwMeter i').forEach(function (bar, i) {
            bar.className = input.value && i < result.score ? 'on-' + result.score : '';
          });
          if (!input.value) { report.innerHTML = ''; return; }
          report.innerHTML = html`
            <div class="entry">
              <span class="ico ${result.score >= 3 ? 'clear' : result.score >= 2 ? 'warn' : 'alert'}">
                ${result.score >= 3 ? '✓' : '!'}
              </span>
              <div class="body">
                <b>${result.label} · ${result.entropy} bits of effective entropy</b>
                <small>${result.notes.length ? result.notes.join(' ') : result.advice}</small>
              </div>
            </div>`;
        });

        root.querySelector('#pwBreach').addEventListener('click', function () {
          var value = input.value;
          var out = root.querySelector('#pwBreachOut');
          if (!value) { UI.toast('Type a password first.', 'warn'); return; }
          out.innerHTML = html`<p class="tiny" style="margin-top:.75rem">Checking…</p>`;
          Engine.breachCheck(value).then(function (result) {
            if (!result.available) {
              out.innerHTML = html`<div class="form-error">${result.reason}</div>`;
              return;
            }
            Store.logActivity('Checked a password against breaches', 'scan', { found: result.count > 0 });
            out.innerHTML = result.count > 0
              ? html`<div class="form-error">
                  <b>Found in breach data ${result.count.toLocaleString()} times.</b>
                  Stop using it anywhere. It is already in the wordlists attackers try first.
                </div>`
              : html`<div class="form-note">
                  <b>Not found in the breach corpus.</b>
                  That is a good sign, but it only means this password has not leaked yet. Strength still matters.
                </div>`;
          });
        });

        root.querySelector('#genPhrase').addEventListener('click', function () {
          genOut.value = Engine.generatePassphrase(4);
        });
        root.querySelector('#genRandom').addEventListener('click', function () {
          genOut.value = Engine.generatePassword(20);
        });
        root.querySelector('#genCopy').addEventListener('click', function () {
          if (!genOut.value) { UI.toast('Generate one first.', 'warn'); return; }
          UI.copy(genOut.value);
        });

        genOut.value = Engine.generatePassphrase(4);
      }
    };
  }

  /* =========================================================
     File fingerprint
     ========================================================= */

  function files() {
    return {
      title: 'File fingerprint',
      subtitle: 'Hash a file locally and look it up',
      body: html`
        <div class="page-head">
          <h1>File fingerprint</h1>
          <p>
            The file is read into memory on this device and hashed with Web Crypto.
            It is never uploaded — you can disconnect from the network and this still works.
          </p>
        </div>

        ${raw(howto('How to use this', [
          'Choose the file you are unsure about — an APK, an installer, an attachment.',
          'Wait for the SHA-256 to appear. Large files take a few seconds.',
          'Select <b>Look up on VirusTotal</b>. That opens a search for the <em>hash only</em> — the file itself still never leaves your device.',
          'If VirusTotal has no record, that means nobody has submitted this exact file before. For a supposedly popular app, that is itself suspicious.'
        ]))}

        <div class="card">
          <div class="field">
            <label for="fileIn">Choose a file</label>
            <input class="input" id="fileIn" type="file">
          </div>
          <div id="fileOut"></div>
        </div>`,

      mount: function (root) {
        var out = root.querySelector('#fileOut');
        root.querySelector('#fileIn').addEventListener('change', function (e) {
          var file = e.target.files && e.target.files[0];
          if (!file) return;
          out.innerHTML = html`<p class="tiny">Reading ${file.name}…</p>`;

          Engine.hashFile(file, function (pct) {
            out.innerHTML = html`<p class="tiny">Reading ${file.name} — ${pct}%</p>`;
          })
            .then(function (result) {
              Store.logActivity('Fingerprinted a file', 'scan', { name: result.name, size: result.size });
              var warnings = result.warnings.map(function (w) {
                return html`<div class="finding high"><div><b>Heads up</b><p>${w}</p></div></div>`;
              }).join('');

              out.innerHTML = html`
                <div class="verdict ${result.warnings.length ? 'caution' : 'clear'}" style="margin-top:1rem">
                  <div class="verdict-head">
                    <span class="sigil">${result.warnings.length ? '!' : '✓'}</span>
                    <div><h3>${result.name}</h3><p>${UI.bytes(result.size)} · ${result.type}</p></div>
                  </div>
                  ${raw(warnings ? html`<div class="findings">${raw(warnings)}</div>` : '')}
                  <div class="breakdown">
                    <div style="grid-column:1/-1"><small>SHA-256</small><b id="sha">${result.sha256}</b></div>
                    <div style="grid-column:1/-1"><small>SHA-1</small><b>${result.sha1}</b></div>
                  </div>
                </div>
                <div class="input-group" style="margin-top:.75rem">
                  <button class="btn" id="copyHash">Copy SHA-256</button>
                  <a class="btn btn-primary" target="_blank" rel="noopener noreferrer"
                     href="https://www.virustotal.com/gui/file/${result.sha256}">Look up on VirusTotal</a>
                </div>`;

              root.querySelector('#copyHash').addEventListener('click', function () {
                UI.copy(result.sha256);
              });
            })
            .catch(function (err) {
              out.innerHTML = html`<div class="form-error">${err.message}</div>`;
            });
        });
      }
    };
  }

  /* =========================================================
     Device posture
     ========================================================= */

  function device() {
    return {
      title: 'Device posture',
      subtitle: 'What this browser reports about itself',
      body: html`
        <div class="page-head">
          <h1>Device posture</h1>
          <p>
            Every line below is read live from this browser. There is a hard limit to what a
            web page can see — it cannot check whether your phone is rooted, whether the OS is
            patched, or what apps are installed. Those need an installed agent.
          </p>
        </div>

        ${raw(howto('How to read this', [
          'Green means the check passed. Amber means it is worth changing. Red means fix it now.',
          'Lines marked as information are context, not problems — they do not affect the score.',
          'Each failing check tells you exactly where the setting lives.',
          'Re-run after changing a setting to confirm it took effect.'
        ]))}

        <div class="grid wide-left">
          <div class="card">
            <div class="card-head"><div><h2>Checks</h2><p>Weighted into the posture score</p></div>
              <button class="btn btn-sm" id="reScan">Re-run</button></div>
            <div class="checks" id="checkList"></div>
          </div>

          <div>
            <div class="card">
              <div class="card-head"><div><h2>Site permissions</h2><p>What this origin currently holds</p></div></div>
              <div id="permList"><p class="tiny">Reading…</p></div>
              <p class="tiny" style="margin-top:.75rem">
                To change these: browser menu → site settings → permissions. Granted camera,
                microphone or location on a site you do not recognise is worth revoking today.
              </p>
            </div>

            <div class="card" style="margin-top:1rem">
              <div class="card-head"><div><h2>Local storage use</h2><p>Space this origin occupies</p></div></div>
              <div id="storageOut"><p class="tiny">Reading…</p></div>
            </div>
          </div>
        </div>`,

      mount: function (root) {
        function drawChecks() {
          var checks = Engine.devicePosture();
          root.querySelector('#checkList').innerHTML = checks.map(function (c) {
            var glyph = c.state === 'pass' ? '✓' : c.state === 'warn' ? '!' : c.state === 'fail' ? '✕' : 'i';
            return html`
              <div class="check ${c.state}">
                <span class="state">${glyph}</span>
                <div>
                  <b>${c.label}</b>
                  <p>${c.detail}</p>
                  ${raw(c.fix && c.state !== 'pass' ? html`<div class="fix">Fix: ${c.fix}</div>` : '')}
                </div>
                <span class="pill ${c.state === 'pass' ? 'clear' : c.state === 'warn' ? 'warn' : c.state === 'fail' ? 'alert' : ''}">${c.state}</span>
              </div>`;
          }).join('');
        }

        drawChecks();
        root.querySelector('#reScan').addEventListener('click', function () {
          drawChecks();
          UI.toast('Checks re-run.', 'clear');
        });

        Engine.permissionAudit().then(function (perms) {
          root.querySelector('#permList').innerHTML = perms.map(function (p) {
            var tone = p.state === 'granted' ? 'warn' : p.state === 'denied' ? 'clear' : '';
            return html`
              <div class="setting">
                <div class="body"><b>${p.name}</b><small>${p.note || 'Current state for this site'}</small></div>
                <span class="pill ${tone}">${p.state}</span>
              </div>`;
          }).join('');
        });

        Engine.storageEstimate().then(function (est) {
          var box = root.querySelector('#storageOut');
          if (!est) {
            box.innerHTML = html`<p class="tiny">This browser does not report storage usage.</p>`;
            return;
          }
          var pct = est.quota ? Math.round((est.usage / est.quota) * 100) : 0;
          box.innerHTML = html`
            <div class="readout"><b>${UI.bytes(est.usage)}</b><span>of ${UI.bytes(est.quota)}</span></div>
            <div class="meter"><i style="width:${Math.max(pct, 1)}%"></i></div>
            <p class="tiny" style="margin-top:.5rem">${pct}% used. Your accounts, settings and encrypted vault live in here.</p>`;
        });

        Store.logActivity('Opened device posture', 'view');
      }
    };
  }

  /* =========================================================
     Encrypted vault
     ========================================================= */

  function vault() {
    return {
      title: 'Vault',
      subtitle: 'Encrypted notes for recovery codes',
      body: html`
        <div class="page-head">
          <h1>Vault</h1>
          <p>
            AES-GCM with a key derived from your passphrase (PBKDF2-SHA256, 210,000 rounds).
            The passphrase is never stored. Lose it and the contents are gone — that is the point.
          </p>
        </div>

        ${raw(howto('What to keep in here', [
          'Two-factor recovery codes — the ones you get once and never look at again.',
          'Your device IMEI numbers. Dial <span class="mono">*#06#</span> on the phone to see them. Police reports need these.',
          'The serial numbers of anything you would report stolen.',
          'Not your passwords — a password manager does that job better.'
        ]))}

        <div class="grid two">
          <div class="card">
            <div class="card-head"><div><h2>Write</h2><p>Encrypted before it is saved</p></div></div>
            <div class="field">
              <label for="vNote">Notes</label>
              <textarea class="input" id="vNote" placeholder="Recovery codes, IMEI numbers, serials…"></textarea>
            </div>
            <div class="field">
              <label for="vPass">Passphrase</label>
              <input class="input" id="vPass" type="password" placeholder="A phrase only you know">
            </div>
            <button class="btn btn-primary btn-block" id="vSave">Encrypt and save</button>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Read</h2><p>Decrypts in memory only</p></div>
              <span class="pill ${Store.vaultExists() ? 'clear' : ''}">${Store.vaultExists() ? 'vault present' : 'empty'}</span></div>
            <div class="field">
              <label for="vPass2">Passphrase</label>
              <input class="input" id="vPass2" type="password" placeholder="Your passphrase">
            </div>
            <button class="btn btn-block" id="vOpen">Unlock</button>
            <div id="vOut"></div>
            <button class="btn btn-danger btn-block" id="vClear" style="margin-top:.75rem">Delete the vault</button>
          </div>
        </div>`,

      mount: function (root) {
        root.querySelector('#vSave').addEventListener('click', function () {
          var note = root.querySelector('#vNote').value;
          var pass = root.querySelector('#vPass').value;
          if (!note.trim()) { UI.toast('Write something first.', 'warn'); return; }
          if (pass.length < 8) { UI.toast('Use a passphrase of at least 8 characters.', 'warn'); return; }
          Store.vaultSave(pass, note).then(function () {
            UI.toast('Encrypted and saved.', 'clear');
            Store.logActivity('Saved to the vault', 'vault');
            root.querySelector('#vNote').value = '';
            root.querySelector('#vPass').value = '';
          }).catch(function (err) {
            UI.toast(err.message, 'alert');
          });
        });

        root.querySelector('#vOpen').addEventListener('click', function () {
          var out = root.querySelector('#vOut');
          Store.vaultLoad(root.querySelector('#vPass2').value)
            .then(function (text) {
              out.innerHTML = html`<div class="form-note" style="white-space:pre-wrap;word-break:break-word">${text}</div>`;
              Store.logActivity('Opened the vault', 'vault');
            })
            .catch(function (err) {
              out.innerHTML = html`<div class="form-error">${err.message}</div>`;
            });
        });

        root.querySelector('#vClear').addEventListener('click', function () {
          UI.confirmAction({
            title: 'Delete the vault?',
            message: 'Everything stored in it is removed from this browser.',
            warning: 'There is no copy. Without the passphrase nobody can recover it, including you.',
            danger: true,
            confirmLabel: 'Delete it'
          }).then(function (ok) {
            if (!ok) return;
            Store.vaultClear();
            Store.logActivity('Deleted the vault', 'vault');
            UI.toast('Vault deleted.', 'clear');
          });
        });
      }
    };
  }

  /* =========================================================
     Incident playbook
     ========================================================= */

  var PLAYBOOK = [
    {
      id: 'locate',
      title: 'Find or lock it from the official service',
      detail: 'Android: open <b>android.com/find</b> on any device and sign in. iPhone: <b>icloud.com/find</b>. Mark it lost — that locks the screen and shows a message with a contact number without wiping anything yet.'
    },
    {
      id: 'sim',
      title: 'Call your network and bar the SIM',
      detail: 'Do this before anything else if the phone receives your banking OTPs. A barred SIM stops a stranger receiving codes in your name. Ask for a replacement on the same number.'
    },
    {
      id: 'bank',
      title: 'Freeze banking and transfer apps',
      detail: 'Use your bank\'s app on another device or their phone line. Ask for a channel block, not just a card block — mobile and USSD are separate channels.'
    },
    {
      id: 'sessions',
      title: 'Sign the device out of your accounts',
      detail: 'Google: myaccount.google.com → Security → Your devices. Apple: appleid.apple.com → Devices. Also WhatsApp (Linked devices) and any email account. Signing out remotely kills an already-open session.'
    },
    {
      id: 'passwords',
      title: 'Change the passwords that were saved on it',
      detail: 'Start with the email account that can reset everything else. Then anything with money attached. Turn on two-factor while you are there.'
    },
    {
      id: 'report',
      title: 'Report it with the IMEI',
      detail: 'File a police report and give them the IMEI. Report it to your network too — they can blacklist the handset so it cannot be used on local networks.'
    },
    {
      id: 'wipe',
      title: 'Erase it — last, not first',
      detail: 'Erasing usually ends your ability to locate it. Only do this once you accept the phone is gone, or if it holds something you cannot risk being read.'
    }
  ];

  function incident() {
    var done = Store.prefs().playbook || {};
    var completed = PLAYBOOK.filter(function (s) { return done[s.id]; }).length;

    return {
      title: 'Incident playbook',
      subtitle: 'Lost or stolen device',
      body: html`
        <div class="page-head">
          <div class="row">
            <div>
              <h1>Your phone is gone. Work down this list.</h1>
              <p>
                The order matters more than the speed. Locking and barring the SIM come before
                erasing, because erasing usually ends your ability to find the device.
              </p>
            </div>
            <span class="pill ${completed === PLAYBOOK.length ? 'clear' : 'amber'}">${completed}/${PLAYBOOK.length} done</span>
          </div>
        </div>

        <div class="guardrail" style="margin-bottom:1.5rem">
          <div>
            <b>Read this before you look for a "locate" button here</b>
            <p>
              No website can locate, lock or wipe a phone it does not manage — not this one,
              not any other. Anything claiming otherwise is either lying or is malware. The
              real controls live with Google, Apple and your mobile network, and the steps
              below take you straight to them.
            </p>
          </div>
        </div>

        <div class="grid wide-left">
          <div class="card">
            <div class="card-head"><div><h2>Steps</h2><p>Tick them off as you go — progress is saved</p></div>
              <button class="btn btn-sm" id="resetPlaybook">Reset</button></div>
            <div class="playbook" id="playbook"></div>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Official services</h2><p>The only places these actions really work</p></div></div>
            <div class="rows">
              <a class="entry" href="https://www.google.com/android/find" target="_blank" rel="noopener noreferrer">
                <span class="ico info">A</span>
                <div class="body"><b>Find My Device (Android)</b><small>Locate, ring, lock or erase an Android phone</small></div>
              </a>
              <a class="entry" href="https://www.icloud.com/find" target="_blank" rel="noopener noreferrer">
                <span class="ico info">i</span>
                <div class="body"><b>Find My (Apple)</b><small>Same controls for iPhone and iPad</small></div>
              </a>
              <a class="entry" href="https://myaccount.google.com/device-activity" target="_blank" rel="noopener noreferrer">
                <span class="ico info">G</span>
                <div class="body"><b>Google device activity</b><small>Sign the missing device out of your account</small></div>
              </a>
              <a class="entry" href="https://appleid.apple.com" target="_blank" rel="noopener noreferrer">
                <span class="ico info">A</span>
                <div class="body"><b>Apple ID devices</b><small>Remove a device from your Apple account</small></div>
              </a>
            </div>
            <p class="tiny" style="margin-top:1rem">
              Save your IMEI in the vault before you need it. Dial <span class="mono">*#06#</span> on the phone to see it.
            </p>
          </div>
        </div>`,

      mount: function (root, ctx) {
        function draw() {
          var state = Store.prefs().playbook || {};
          root.querySelector('#playbook').innerHTML = PLAYBOOK.map(function (step) {
            return html`
              <div class="step ${state[step.id] ? 'done' : ''}">
                <div><b>${step.title}</b><p>${raw(step.detail)}</p></div>
                <label class="switch">
                  <input type="checkbox" data-step="${step.id}" ${raw(state[step.id] ? 'checked' : '')}>
                  <i></i>
                </label>
              </div>`;
          }).join('');

          root.querySelectorAll('[data-step]').forEach(function (box) {
            box.addEventListener('change', function () {
              var state2 = Store.prefs().playbook || {};
              state2[box.getAttribute('data-step')] = box.checked;
              Store.setPref('playbook', state2);
              Store.logActivity(
                (box.checked ? 'Completed' : 'Reopened') + ' playbook step',
                'incident',
                { step: box.getAttribute('data-step') }
              );
              draw();
            });
          });
        }

        draw();
        root.querySelector('#resetPlaybook').addEventListener('click', function () {
          Store.setPref('playbook', {});
          draw();
          UI.toast('Playbook reset.', 'clear');
        });
      }
    };
  }

  /* =========================================================
     Activity
     ========================================================= */

  function activity(ctx) {
    var mine = Store.activity({ userId: ctx.user.id });

    return {
      title: 'My activity',
      subtitle: 'Everything this account has done',
      body: html`
        <div class="page-head">
          <div class="row">
            <div>
              <h1>My activity</h1>
              <p>Recorded on this device. The administrator of this deployment can see the same record.</p>
            </div>
            <button class="btn" id="exportMine">Download CSV</button>
          </div>
        </div>

        <div class="table-wrap">
          <table>
            <thead><tr><th>When</th><th>Action</th><th>Type</th><th>Detail</th></tr></thead>
            <tbody>
              ${raw(mine.length ? mine.slice(0, 120).map(function (e) {
                return html`<tr>
                  <td class="mono nowrap">${UI.fullDate(e.at)}</td>
                  <td>${e.action}</td>
                  <td><span class="pill">${e.category}</span></td>
                  <td class="mono dim">${Object.keys(e.meta).length ? JSON.stringify(e.meta) : '—'}</td>
                </tr>`;
              }).join('') : html`<tr><td colspan="4"><div class="empty"><b>Nothing logged yet</b><p>Run a scan or open a tool and it will appear here.</p></div></td></tr>`)}
            </tbody>
          </table>
        </div>`,

      mount: function (root, ctx2) {
        root.querySelector('#exportMine').addEventListener('click', function () {
          var rows = [['Timestamp', 'Action', 'Category', 'Detail']].concat(
            Store.activity({ userId: ctx2.user.id }).map(function (e) {
              return [new Date(e.at).toISOString(), e.action, e.category, JSON.stringify(e.meta)];
            })
          );
          UI.download('xadon-my-activity.csv', UI.toCsv(rows), 'text/csv;charset=utf-8');
          UI.toast('Downloaded.', 'clear');
        });
      }
    };
  }

  /* =========================================================
     Guide
     ========================================================= */

  function guide() {
    return {
      title: 'Guide',
      subtitle: 'What each tool does and when to use it',
      body: html`
        <div class="page-head">
          <h1>Guide</h1>
          <p>What this console can do, what it cannot, and how to get a useful answer out of it.</p>
        </div>

        <div class="grid two">
          <div class="card">
            <div class="card-head"><div><h2>Link inspector</h2></div></div>
            <p class="small dim">Copy a link instead of tapping it, paste it in, read the findings. It checks the scheme, hidden credentials before an @ sign, raw IP addresses, punycode and mixed alphabets, look-alike domains within two letters of a real brand, shorteners, high-abuse endings, subdomain depth, odd ports, credential words in the path, double file extensions and open redirects.</p>
            <p class="small dim">It cannot tell you whether a page has been hacked since it was last checked. A clean result means "no known warning patterns", not "safe".</p>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Message inspector</h2></div></div>
            <p class="small dim">Paste the whole message. It matches fourteen fraud patterns — OTP and BVN requests, account-suspension threats, manufactured deadlines, prize claims, investment pitches, delivery fees, "this is my new number", gift card demands, pay-to-work offers, remote-access requests and more — and runs the full link inspection on anything inside.</p>
            <p class="small dim">A clean result on a message asking you for money still means: verify it another way.</p>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Password check</h2></div></div>
            <p class="small dim">Strength is scored on real entropy, then penalised for the patterns cracking tools try first: common words, repeated characters, years, word-then-digits, keyboard runs. The breach lookup sends only the first five characters of a SHA-1 hash, so the password itself never leaves the device.</p>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>File fingerprint</h2></div></div>
            <p class="small dim">Computes SHA-256 and SHA-1 on your machine using Web Crypto. Use the hash to look the file up on VirusTotal without uploading it. No known record for a supposedly popular app is a warning sign in itself.</p>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Device posture</h2></div></div>
            <p class="small dim">Reads what the browser will tell it: secure context, Web Crypto availability, automation flags, storage and cookie access, tracking preference, network type, locale consistency. Each failing check names the setting to change.</p>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Vault</h2></div></div>
            <p class="small dim">AES-GCM encryption with a PBKDF2-derived key. Good for recovery codes and IMEI numbers. The passphrase is never stored anywhere, so there is no recovery path if you forget it.</p>
          </div>

          <div class="card span-all">
            <div class="card-head"><div><h2>What this cannot do</h2><p>Stated plainly, because plenty of products in this space are not honest about it</p></div></div>
            <div class="checks">
              <div class="check fail"><span class="state">✕</span><div><b>Scan another phone's files</b><p>A web page has no access to a device's file system. Real device scanning needs an installed app with OS-level permissions.</p></div><span class="pill alert">not possible</span></div>
              <div class="check fail"><span class="state">✕</span><div><b>Locate, lock or wipe a phone</b><p>Those actions require the device to be enrolled with Google, Apple or a mobile device management provider. The incident playbook links to the real ones.</p></div><span class="pill alert">not possible</span></div>
              <div class="check fail"><span class="state">✕</span><div><b>Block a call or intercept a text</b><p>Browsers have no access to the telephony stack. That is an OS-level permission on Android and unavailable on iOS.</p></div><span class="pill alert">not possible</span></div>
              <div class="check warn"><span class="state">!</span><div><b>Prove a site is safe</b><p>No tool can. Pattern analysis lowers your odds of being caught; it does not remove the risk.</p></div><span class="pill warn">limited</span></div>
            </div>
          </div>
        </div>`,
      mount: function () {}
    };
  }

  /* =========================================================
     Community / GitHub
     ========================================================= */

  function community() {
    var cfg = window.XADON_CONFIG;
    return {
      title: 'Community',
      subtitle: 'The code behind this',
      body: html`
        <div class="page-head">
          <h1>Built by ${cfg.creator}</h1>
          <p>
            Every public repository on
            <a href="https://github.com/${cfg.githubUser}" target="_blank" rel="noopener noreferrer">github.com/${cfg.githubUser}</a>,
            loaded live from the GitHub API. If the work is useful, a star costs nothing and helps a lot.
          </p>
        </div>

        <div class="card" style="margin-bottom:1rem">
          <div class="card-head">
            <div><h2>Star the repositories</h2><p>Opens each one on GitHub so you can star it there</p></div>
            <button class="btn btn-primary star-btn" id="starAll">${raw(UI.starIcon())} Open all to star</button>
          </div>
          <p class="tiny">
            GitHub only lets you star while signed in to GitHub itself, so these buttons take you
            to the repository page rather than starring from here. Anything else would need your
            GitHub password, and no site should ever ask for that.
          </p>
        </div>

        <div id="repoBox"><p class="tiny">Loading repositories…</p></div>`,

      mount: function (root) {
        var box = root.querySelector('#repoBox');
        var repos = [];

        fetch('https://api.github.com/users/' + cfg.githubUser + '/repos?per_page=100&sort=updated')
          .then(function (res) {
            if (!res.ok) throw new Error(res.status === 403
              ? 'GitHub is rate-limiting this address. Try again in a few minutes.'
              : 'GitHub returned ' + res.status + '.');
            return res.json();
          })
          .then(function (list) {
            repos = list;
            if (!list.length) {
              box.innerHTML = html`<div class="card"><div class="empty"><b>No public repositories yet</b><p>Once ${cfg.githubUser} publishes one it shows up here automatically.</p></div></div>`;
              return;
            }
            box.innerHTML = html`
              <div class="repo-grid">
                ${raw(list.map(function (r) {
                  return html`
                    <div class="repo">
                      <b>${r.name}</b>
                      <p>${r.description || 'No description yet.'}</p>
                      <div class="repo-foot">
                        <span>★ ${r.stargazers_count}</span>
                        <span>${r.language || '—'}</span>
                        <a class="btn btn-sm star-btn" href="${r.html_url}" target="_blank" rel="noopener noreferrer">
                          ${raw(UI.starIcon())} Star
                        </a>
                      </div>
                    </div>`;
                }).join(''))}
              </div>`;
          })
          .catch(function (err) {
            box.innerHTML = html`
              <div class="card">
                <div class="form-error">${err.message}</div>
                <a class="btn" style="margin-top:.75rem" href="https://github.com/${cfg.githubUser}" target="_blank" rel="noopener noreferrer">Open the GitHub profile instead</a>
              </div>`;
          });

        root.querySelector('#starAll').addEventListener('click', function () {
          if (!repos.length) {
            window.open('https://github.com/' + cfg.githubUser + '?tab=repositories', '_blank', 'noopener');
            return;
          }
          UI.confirmAction({
            title: 'Open ' + repos.length + ' tabs?',
            message: 'Each repository opens in its own tab so you can star it. Your browser will probably ask permission for the pop-ups.',
            confirmLabel: 'Open them'
          }).then(function (ok) {
            if (!ok) return;
            repos.slice(0, 12).forEach(function (r, i) {
              setTimeout(function () { window.open(r.html_url, '_blank', 'noopener'); }, i * 220);
            });
            Store.logActivity('Opened repositories to star', 'community', { count: Math.min(repos.length, 12) });
          });
        });
      }
    };
  }

  /* =========================================================
     Settings
     ========================================================= */

  function settings(ctx) {
    var user = ctx.user;
    return {
      title: 'Settings',
      subtitle: 'Your account and your data',
      body: html`
        <div class="page-head">
          <h1>Settings</h1>
          <p>Your profile, your data, and how to leave.</p>
        </div>

        <div class="grid two">
          <div class="card">
            <div class="card-head"><div><h2>Profile</h2><p>Shown across the console</p></div></div>
            <div class="field">
              <label for="s-name">Name</label>
              <input class="input" id="s-name" value="${user.name}">
            </div>
            <div class="field">
              <label for="s-ws">Workspace name</label>
              <input class="input" id="s-ws" value="${user.workspace || ''}">
            </div>
            <div class="field">
              <label>Email</label>
              <input class="input" value="${user.email}" disabled>
              <div class="hint">Signed in with ${user.provider === 'google' ? 'Google' : 'a password'}. The email cannot be changed here.</div>
            </div>
            <button class="btn btn-primary" id="saveProfile">Save changes</button>
          </div>

          <div class="card">
            <div class="card-head"><div><h2>Your data</h2><p>Everything is stored in this browser</p></div></div>
            <div class="setting">
              <div class="body"><b>Download my data</b><small>Account record and full activity log as JSON</small></div>
              <button class="btn btn-sm" id="exportMe">Download</button>
            </div>
            <div class="setting">
              <div class="body"><b>Sign out</b><small>Ends the session on this browser</small></div>
              <button class="btn btn-sm" id="signOut">Sign out</button>
            </div>
            <div class="setting">
              <div class="body"><b>Delete my account</b><small>Removes the account, its activity and the vault</small></div>
              <button class="btn btn-sm btn-danger" id="deleteMe">Delete</button>
            </div>

            <div class="guardrail" style="margin-top:1rem">
              <div>
                <b>Where your data lives</b>
                <p>
                  In this browser's local storage, on this device only. Clearing site data removes
                  it permanently. Nothing syncs, because there is no server yet.
                </p>
              </div>
            </div>
          </div>
        </div>`,

      mount: function (root, ctx2) {
        root.querySelector('#saveProfile').addEventListener('click', function () {
          var name = root.querySelector('#s-name').value.trim();
          if (!name) { UI.toast('The name cannot be empty.', 'warn'); return; }
          Store.updateUser(ctx2.user.id, {
            name: name,
            workspace: root.querySelector('#s-ws').value.trim()
          });
          Store.logActivity('Updated profile', 'account');
          UI.toast('Saved.', 'clear');
          ctx2.navigate('/console/settings');
        });

        root.querySelector('#exportMe').addEventListener('click', function () {
          var payload = {
            account: Object.assign({}, ctx2.user, { hash: undefined, salt: undefined }),
            activity: Store.activity({ userId: ctx2.user.id })
          };
          UI.download('xadon-my-data.json', JSON.stringify(payload, null, 2), 'application/json');
        });

        root.querySelector('#signOut').addEventListener('click', function () {
          Store.endSession();
          ctx2.navigate('/signin');
          UI.toast('Signed out.', 'clear');
        });

        root.querySelector('#deleteMe').addEventListener('click', function () {
          UI.confirmAction({
            title: 'Delete your account?',
            message: 'Your account, activity log and vault are removed from this browser.',
            warning: 'This cannot be undone and nothing is backed up.',
            danger: true,
            confirmLabel: 'Delete everything'
          }).then(function (ok) {
            if (!ok) return;
            Store.vaultClear();
            Store.deleteUser(ctx2.user.id);
            Store.endSession();
            ctx2.navigate('/signup');
            UI.toast('Account deleted.', 'clear');
          });
        });
      }
    };
  }

  window.XadonPages = {
    overview: overview,
    links: links,
    messages: messages,
    passwords: passwords,
    files: files,
    device: device,
    vault: vault,
    incident: incident,
    activity: activity,
    guide: guide,
    community: community,
    settings: settings
  };
})();
