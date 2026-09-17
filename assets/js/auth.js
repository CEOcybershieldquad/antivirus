/* ============================================================
   Authentication screens
   Sign up, sign in, Google sign-in, admin portal.

   Rule enforced here: you cannot sign in to an account that was
   never created. verifyPassword() rejects unknown emails with a
   message that points to the sign-up tab.
   ============================================================ */

(function () {
  'use strict';

  var UI = window.XadonUI;
  var Store = window.XadonStore;
  var Engine = window.XadonEngine;
  var html = UI.html;
  var raw = UI.raw;

  var googleScriptLoaded = false;

  /* ---------------------------------------------------------
     Google sign-in
     --------------------------------------------------------- */

  function decodeJwtPayload(token) {
    try {
      var part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      var pad = part.length % 4 ? '='.repeat(4 - (part.length % 4)) : '';
      var json = decodeURIComponent(
        atob(part + pad)
          .split('')
          .map(function (c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); })
          .join('')
      );
      return JSON.parse(json);
    } catch (err) {
      return null;
    }
  }

  function handleGoogleCredential(response, onDone) {
    /* The signature is NOT verified here. A browser cannot keep a
       verification secret, so this only proves the token parses.
       A production build must POST response.credential to a server
       and verify it against Google's public keys before trusting
       any field inside it. */
    var claims = decodeJwtPayload(response.credential);
    if (!claims || !claims.email) {
      UI.toast('Google returned a token this app could not read. Try again.', 'alert');
      return;
    }

    var existing = Store.findByEmail(claims.email);
    var promise = existing
      ? Promise.resolve(existing)
      : Store.createAccount({
        provider: 'google',
        name: claims.name || claims.email.split('@')[0],
        email: claims.email,
        picture: claims.picture || ''
      });

    promise
      .then(function (user) {
        if (user.status === 'suspended') {
          throw new Error('This account is suspended. Contact ' + window.XADON_CONFIG.supportEmail + '.');
        }
        Store.startSession(user);
        UI.toast('Signed in as ' + user.email + '.', 'clear');
        onDone('/console');
      })
      .catch(function (err) { UI.toast(err.message, 'alert'); });
  }

  function mountGoogle(onDone) {
    var clientId = (window.XADON_CONFIG.googleClientId || '').trim();
    var mount = document.getElementById('googleMount');
    if (!mount) return;

    if (!clientId) return; /* fallback panel shows via CSS */

    function init() {
      if (!window.google || !window.google.accounts || !window.google.accounts.id) return;
      window.google.accounts.id.initialize({
        client_id: clientId,
        callback: function (res) { handleGoogleCredential(res, onDone); },
        auto_select: false,
        cancel_on_tap_outside: true
      });
      window.google.accounts.id.renderButton(mount, {
        theme: 'outline',
        size: 'large',
        width: mount.offsetWidth || 320,
        text: 'continue_with',
        shape: 'rectangular'
      });
    }

    if (googleScriptLoaded && window.google) { init(); return; }

    var script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = function () { googleScriptLoaded = true; init(); };
    script.onerror = function () {
      mount.innerHTML = html`<div class="form-error">Could not load Google sign-in. Check the connection, or that this origin is listed in your Google Cloud credentials.</div>`;
    };
    document.head.appendChild(script);
  }

  /* ---------------------------------------------------------
     Sign in / sign up screen
     --------------------------------------------------------- */

  function authScreen(mode, navigate, mount) {
    var cfg = window.XADON_CONFIG;
    var isSignup = mode === 'signup';

    mount.innerHTML = html`
      <div class="auth">
        <div class="auth-body">
          <section class="auth-pitch">
            <div class="brandmark">
              <span class="glyph">◈</span>
              <b>XADON</b><span>Phone Defense</span>
            </div>

            <h1>Check the link before you tap it.</h1>
            <p>
              A working security console for people who handle their own risk. Paste a
              link, a text message, a password or a file, and get a real answer with the
              reasoning shown — not a spinner and a green tick.
            </p>

            <div class="capability-list">
              <div><i>✓</i><span><b>Link inspector.</b> Punycode, look-alike domains, hidden redirects, credential traps.</span></div>
              <div><i>✓</i><span><b>Message inspector.</b> Fourteen fraud patterns, tuned for SMS and WhatsApp scams.</span></div>
              <div><i>✓</i><span><b>Breach lookup.</b> Checks a password against known breaches without ever sending it.</span></div>
              <div><i>✓</i><span><b>File fingerprint.</b> SHA-256 computed on your machine. Nothing uploads.</span></div>
              <div><i>✓</i><span><b>Device posture.</b> Live signals from this browser, scored and explained.</span></div>
              <div><i>✓</i><span><b>Encrypted vault.</b> AES-GCM notes for recovery codes, locked to a passphrase.</span></div>
            </div>
          </section>

          <section class="auth-card">
            <div class="auth-switch" role="tablist">
              <button role="tab" aria-selected="${!isSignup}" data-mode="signin">Sign in</button>
              <button role="tab" aria-selected="${isSignup}" data-mode="signup">Create account</button>
            </div>

            <h2>${isSignup ? 'Create your account' : 'Welcome back'}</h2>
            <p class="dim">${isSignup
              ? 'You need an account before you can sign in. It takes about twenty seconds.'
              : 'Sign in with the account you created, or continue with Google.'}</p>

            <form id="authForm" novalidate>
              ${raw(isSignup ? html`
                <div class="field">
                  <label for="f-name">Full name</label>
                  <input class="input" id="f-name" autocomplete="name" placeholder="Ada Lovelace" required>
                </div>` : '')}

              <div class="field">
                <label for="f-email">Email address</label>
                <input class="input" id="f-email" type="email" autocomplete="email" placeholder="you@example.com" required>
              </div>

              <div class="field">
                <label for="f-pass">Password</label>
                <input class="input" id="f-pass" type="password"
                       autocomplete="${isSignup ? 'new-password' : 'current-password'}"
                       placeholder="${isSignup ? 'At least 12 characters' : 'Your password'}" required>
                ${raw(isSignup ? `
                  <div class="strength-meter" id="meter" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
                  <div class="hint" id="strengthNote">Four unrelated words beat one clever word. <button type="button" class="btn-ghost btn-sm" id="suggestPass" style="padding:0;text-decoration:underline">Suggest one</button></div>
                ` : '')}
              </div>

              ${raw(isSignup ? html`
                <div class="field">
                  <label for="f-pass2">Confirm password</label>
                  <input class="input" id="f-pass2" type="password" autocomplete="new-password" required>
                </div>` : '')}

              <button class="btn btn-primary btn-block" type="submit" id="authSubmit">
                ${isSignup ? 'Create account' : 'Sign in'}
              </button>
              <div id="authError"></div>
            </form>

            <div class="divider">or</div>

            <div id="googleMount"></div>
            <div class="google-fallback">
              <button class="google-btn" id="googleInfo" type="button">
                ${raw(UI.googleIcon())} Continue with Google
              </button>
              <p class="tiny" style="margin-top:.5rem">
                Google sign-in needs a Client ID. Add one in <span class="mono">assets/js/config.js</span> and redeploy — tap the button for the exact steps.
              </p>
            </div>

            <p class="tiny" style="margin-top:1.25rem">
              Accounts are stored in this browser and passwords are hashed with PBKDF2-SHA256.
              That is the right algorithm but the wrong place — see the README before you take
              real customers. <a href="#" data-go="/admin">Administrator sign-in</a>
            </p>
          </section>
        </div>
        ${raw(UI.footer())}
      </div>`;

    /* tab switching */
    mount.querySelectorAll('[data-mode]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        navigate(btn.getAttribute('data-mode') === 'signup' ? '/signup' : '/signin');
      });
    });

    /* live strength meter */
    var passInput = document.getElementById('f-pass');
    if (isSignup && passInput) {
      passInput.addEventListener('input', function () {
        var result = Engine.scorePassword(passInput.value);
        var bars = document.querySelectorAll('#meter i');
        bars.forEach(function (bar, i) {
          bar.className = i < result.score ? 'on-' + result.score : '';
        });
        var note = document.getElementById('strengthNote');
        if (note && passInput.value) {
          note.innerHTML = html`<b>${result.label}</b> · about ${result.entropy} bits. ${result.notes[0] || result.advice}`;
        }
      });

      var suggest = document.getElementById('suggestPass');
      if (suggest) {
        suggest.addEventListener('click', function () {
          var generated = Engine.generatePassphrase(4);
          passInput.type = 'text';
          passInput.value = generated;
          var confirmField = document.getElementById('f-pass2');
          if (confirmField) confirmField.value = generated;
          passInput.dispatchEvent(new Event('input'));
          UI.toast('Passphrase generated. Save it in your password manager now.', 'clear');
        });
      }
    }

    /* submit */
    document.getElementById('authForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var errorBox = document.getElementById('authError');
      var submit = document.getElementById('authSubmit');
      errorBox.innerHTML = '';
      submit.disabled = true;
      submit.textContent = isSignup ? 'Creating…' : 'Checking…';

      function fail(message) {
        errorBox.innerHTML = html`<div class="form-error">${message}</div>`;
        submit.disabled = false;
        submit.textContent = isSignup ? 'Create account' : 'Sign in';
      }

      var email = document.getElementById('f-email').value;
      var password = document.getElementById('f-pass').value;

      if (isSignup) {
        var name = document.getElementById('f-name').value;
        if (password !== document.getElementById('f-pass2').value) {
          return fail('The two passwords do not match.');
        }
        Store.createAccount({ name: name, email: email, password: password })
          .then(function (user) {
            Store.startSession(user);
            UI.toast('Account created. Welcome, ' + user.name + '.', 'clear');
            navigate('/console');
          })
          .catch(function (err) { fail(err.message); });
      } else {
        Store.verifyPassword(email, password)
          .then(function (user) {
            Store.startSession(user);
            UI.toast('Signed in.', 'clear');
            navigate('/console');
          })
          .catch(function (err) { fail(err.message); });
      }
    });

    /* Google */
    mountGoogle(navigate);
    var infoBtn = document.getElementById('googleInfo');
    if (infoBtn) {
      infoBtn.addEventListener('click', function () {
        UI.modal({
          title: 'Turn on Google sign-in',
          body: html`
            <p class="dim small">It takes about five minutes and costs nothing.</p>
            <div class="playbook" style="margin-top:1rem">
              <div class="step"><div><b>Open Google Cloud Console</b><p>Go to console.cloud.google.com, create a project (or pick one), then open APIs &amp; Services → Credentials.</p></div></div>
              <div class="step"><div><b>Create an OAuth client ID</b><p>Choose application type “Web application”. Give it any name.</p></div></div>
              <div class="step"><div><b>Add your origin</b><p>Under Authorised JavaScript origins add <span class="mono">https://${location.host}</span>. Leave redirect URIs empty — this uses Google Identity Services, not a redirect flow.</p></div></div>
              <div class="step"><div><b>Paste the Client ID</b><p>Copy it into <span class="mono">googleClientId</span> in <span class="mono">assets/js/config.js</span>, then redeploy. The real Google button replaces this one automatically.</p></div></div>
            </div>
            <div class="guardrail" style="margin-top:1rem">
              <div><b>One more step for production</b><p>This build reads the Google token in the browser, which proves it parses but not that it is genuine. Before you charge anyone, send the token to a server and verify its signature there.</p></div>
            </div>`
        });
      });
    }

    UI.wireRoutes(mount, navigate);
  }

  /* ---------------------------------------------------------
     Admin portal
     --------------------------------------------------------- */

  function adminScreen(navigate, mount) {
    var cfg = window.XADON_CONFIG;

    mount.innerHTML = html`
      <div class="auth">
        <div class="auth-body">
          <section class="auth-pitch">
            <div class="brandmark">
              <span class="glyph">◈</span><b>XADON</b><span>Administrator</span>
            </div>
            <h1>Operator console.</h1>
            <p>
              Every account on this deployment, every session, and a full activity log.
              Use it to see who signed in, what they ran, and where something went wrong.
            </p>
            <div class="capability-list">
              <div><i>✓</i><span><b>Directory.</b> All registered accounts with sign-in counts and status.</span></div>
              <div><i>✓</i><span><b>Activity monitor.</b> A live, filterable log of what everyone does.</span></div>
              <div><i>✓</i><span><b>Controls.</b> Suspend, restore or remove an account; export the record.</span></div>
            </div>
            <div class="guardrail" style="margin-top:2rem">
              <div>
                <b>This gate is not real security</b>
                <p>
                  The admin credentials sit in browser JavaScript, so anyone who opens DevTools
                  can read them. It is fine for a demo or an internal preview. Put admin auth
                  behind a server before this deployment holds anything that matters.
                </p>
              </div>
            </div>
          </section>

          <section class="auth-card">
            <h2>Administrator sign-in</h2>
            <p class="dim">Restricted to the operator of this deployment.</p>

            <form id="adminForm" novalidate>
              <div class="field">
                <label for="a-user">Username</label>
                <input class="input" id="a-user" autocomplete="username" placeholder="admin" required>
              </div>
              <div class="field">
                <label for="a-pass">Password</label>
                <input class="input" id="a-pass" type="password" autocomplete="current-password" required>
              </div>
              <button class="btn btn-primary btn-block" type="submit">Open admin console</button>
              <div id="adminError"></div>
            </form>

            <p class="tiny" style="margin-top:1.25rem">
              <button class="btn-ghost btn-sm" id="adminForgot" style="padding:0;text-decoration:underline">Forgot the admin password?</button>
              · <a href="#" data-go="/signin">Back to user sign-in</a>
            </p>
          </section>
        </div>
        ${raw(UI.footer())}
      </div>`;

    document.getElementById('adminForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var result = Store.adminSignIn(
        document.getElementById('a-user').value,
        document.getElementById('a-pass').value
      );
      if (!result.ok) {
        document.getElementById('adminError').innerHTML = html`<div class="form-error">${result.error}</div>`;
        return;
      }
      UI.toast('Administrator session open.', 'clear');
      navigate('/admin/overview');
    });

    document.getElementById('adminForgot').addEventListener('click', function () {
      openResetFlow(navigate);
    });

    UI.wireRoutes(mount, navigate);
  }

  function openResetFlow(navigate) {
    var cfg = window.XADON_CONFIG;
    var recovery = cfg.admin.recoveryEmail;

    UI.modal({
      title: 'Reset the admin password',
      body: html`
        <p class="dim small">
          A six-character code is issued to the recovery address on file:
          <b class="mono">${recovery}</b>
        </p>

        <div class="guardrail" style="margin:1rem 0">
          <div>
            <b>No mail server is connected</b>
            <p>
              This build cannot send email on its own — a static site has nothing to send it with.
              Tap “Issue code” and it opens a pre-filled draft to ${recovery} so you can send it
              yourself, and shows the code on screen. Wire up a mail API (Resend, Postmark, SES)
              in a serverless function to make this automatic.
            </p>
          </div>
        </div>

        <button class="btn btn-primary btn-block" id="issueCode">Issue reset code</button>
        <div id="codeArea"></div>

        <form id="resetForm" style="margin-top:1.25rem">
          <div class="field">
            <label for="r-code">Reset code</label>
            <input class="input mono" id="r-code" placeholder="A1B2C3" maxlength="6" autocomplete="one-time-code">
          </div>
          <div class="field">
            <label for="r-new">New admin password</label>
            <input class="input" id="r-new" type="password" placeholder="At least 10 characters">
          </div>
          <button class="btn btn-block" type="submit">Set new password</button>
          <div id="resetMsg"></div>
        </form>`,
      onOpen: function (box) {
        box.querySelector('#issueCode').addEventListener('click', function () {
          var code = Store.issueAdminResetCode();
          var subject = encodeURIComponent('XADON admin password reset code');
          var body = encodeURIComponent(
            'Reset code: ' + code + '\n' +
            'Issued: ' + new Date().toLocaleString() + '\n' +
            'Valid for 15 minutes.\n' +
            'Deployment: ' + location.origin + '\n\n' +
            'If you did not request this, someone has access to the admin sign-in page.'
          );
          box.querySelector('#codeArea').innerHTML = html`
            <div class="form-note" style="margin-top:1rem">
              <div>Code: <b class="mono" style="font-size:1.1rem;letter-spacing:.1em">${code}</b></div>
              <div class="tiny" style="margin-top:.5rem">Valid for 15 minutes.</div>
              <a class="btn btn-sm" style="margin-top:.75rem"
                 href="mailto:${recovery}?subject=${raw(subject)}&body=${raw(body)}">
                Open mail draft to ${recovery}
              </a>
            </div>`;
        });

        box.querySelector('#resetForm').addEventListener('submit', function (e) {
          e.preventDefault();
          var result = Store.completeAdminReset(
            box.querySelector('#r-code').value,
            box.querySelector('#r-new').value
          );
          box.querySelector('#resetMsg').innerHTML = result.ok
            ? html`<div class="form-note">Password changed. Sign in with the new one.</div>`
            : html`<div class="form-error">${result.error}</div>`;
          if (result.ok) {
            setTimeout(function () { UI.closeModal(); }, 1600);
          }
        });
      }
    });
  }

  window.XadonAuth = {
    authScreen: authScreen,
    adminScreen: adminScreen
  };
})();
