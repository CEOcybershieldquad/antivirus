/* ============================================================
   Storage layer
   Accounts, sessions and the activity log.

   Passwords are never stored in plain text. Each account keeps a
   random 16-byte salt and a PBKDF2-SHA256 hash at 210,000
   iterations (OWASP 2023 guidance). That is the correct algorithm
   — but it runs in the browser, so a determined person with
   DevTools can still read the stored records. Treat this as a
   working reference implementation to port to a server, not as
   production authentication.
   ============================================================ */

(function () {
  'use strict';

  var KEYS = {
    users: 'xadon.users.v5',
    session: 'xadon.session.v5',
    adminSession: 'xadon.admin.session.v5',
    adminReset: 'xadon.admin.reset.v5',
    activity: 'xadon.activity.v5',
    prefs: 'xadon.prefs.v5',
    vault: 'xadon.vault.v5'
  };

  var ITERATIONS = 210000;

  /* ---------- low-level helpers ---------- */

  function read(key, fallback) {
    try {
      var raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (err) {
      console.warn('[xadon] could not read ' + key, err);
      return fallback;
    }
  }

  function write(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (err) {
      console.warn('[xadon] could not write ' + key, err);
      return false;
    }
  }

  function bytesToHex(buffer) {
    return Array.prototype.map
      .call(new Uint8Array(buffer), function (b) {
        return b.toString(16).padStart(2, '0');
      })
      .join('');
  }

  function hexToBytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  function randomHex(byteLength) {
    var buf = new Uint8Array(byteLength);
    crypto.getRandomValues(buf);
    return bytesToHex(buf);
  }

  function uid(prefix) {
    return (prefix || 'id') + '_' + randomHex(8);
  }

  /* ---------- password hashing ---------- */

  function derive(password, saltHex, iterations) {
    var enc = new TextEncoder();
    return crypto.subtle
      .importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
      .then(function (key) {
        return crypto.subtle.deriveBits(
          {
            name: 'PBKDF2',
            salt: hexToBytes(saltHex),
            iterations: iterations || ITERATIONS,
            hash: 'SHA-256'
          },
          key,
          256
        );
      })
      .then(bytesToHex);
  }

  /* Constant-time-ish comparison. Not a real defence in a browser,
     but it costs nothing and keeps the habit correct. */
  function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
  }

  /* ---------- accounts ---------- */

  function allUsers() {
    return read(KEYS.users, []);
  }

  function saveUsers(list) {
    write(KEYS.users, list);
  }

  function normaliseEmail(email) {
    return String(email || '').trim().toLowerCase();
  }

  function findByEmail(email) {
    var target = normaliseEmail(email);
    return allUsers().filter(function (u) {
      return u.email === target;
    })[0] || null;
  }

  function findById(id) {
    return allUsers().filter(function (u) {
      return u.id === id;
    })[0] || null;
  }

  function createAccount(input) {
    var email = normaliseEmail(input.email);
    var name = String(input.name || '').trim();

    if (!name) return Promise.reject(new Error('Enter the name you want on the account.'));
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return Promise.reject(new Error('That email address does not look valid.'));
    }
    if (findByEmail(email)) {
      return Promise.reject(new Error('An account already uses that email. Sign in instead.'));
    }

    if (input.provider === 'google') {
      var googleUser = {
        id: uid('usr'),
        name: name,
        email: email,
        provider: 'google',
        picture: input.picture || '',
        salt: null,
        hash: null,
        status: 'active',
        role: 'defender',
        createdAt: Date.now(),
        lastLogin: null,
        loginCount: 0,
        workspace: name.split(' ')[0] + "'s workspace"
      };
      var listG = allUsers();
      listG.push(googleUser);
      saveUsers(listG);
      return Promise.resolve(googleUser);
    }

    var strength = window.XadonEngine.scorePassword(input.password || '');
    if (strength.score < 2) {
      return Promise.reject(new Error('That password is too easy to guess. ' + strength.advice));
    }

    var salt = randomHex(16);
    return derive(input.password, salt).then(function (hash) {
      var user = {
        id: uid('usr'),
        name: name,
        email: email,
        provider: 'password',
        picture: '',
        salt: salt,
        hash: hash,
        iterations: ITERATIONS,
        status: 'active',
        role: 'defender',
        createdAt: Date.now(),
        lastLogin: null,
        loginCount: 0,
        workspace: name.split(' ')[0] + "'s workspace"
      };
      var list = allUsers();
      list.push(user);
      saveUsers(list);
      return user;
    });
  }

  function verifyPassword(email, password) {
    var user = findByEmail(email);
    if (!user) {
      return Promise.reject(new Error('No account found for that email. Create one first.'));
    }
    if (user.provider === 'google') {
      return Promise.reject(new Error('This account signs in with Google. Use the Google button.'));
    }
    if (user.status === 'suspended') {
      return Promise.reject(new Error('This account is suspended. Contact ' + window.XADON_CONFIG.supportEmail + '.'));
    }
    return derive(password, user.salt, user.iterations).then(function (hash) {
      if (!safeEqual(hash, user.hash)) {
        throw new Error('That password does not match this account.');
      }
      return user;
    });
  }

  function updateUser(id, patch) {
    var list = allUsers();
    var updated = null;
    list = list.map(function (u) {
      if (u.id !== id) return u;
      updated = Object.assign({}, u, patch);
      return updated;
    });
    saveUsers(list);
    return updated;
  }

  function deleteUser(id) {
    saveUsers(allUsers().filter(function (u) { return u.id !== id; }));
    write(
      KEYS.activity,
      read(KEYS.activity, []).filter(function (a) { return a.userId !== id; })
    );
  }

  /* ---------- sessions ---------- */

  function startSession(user) {
    var session = {
      userId: user.id,
      startedAt: Date.now(),
      agent: navigator.userAgent,
      lastSeen: Date.now()
    };
    write(KEYS.session, session);
    updateUser(user.id, {
      lastLogin: Date.now(),
      loginCount: (user.loginCount || 0) + 1
    });
    logActivity('Signed in', 'auth', { provider: user.provider }, user.id);
    return session;
  }

  function currentSession() {
    return read(KEYS.session, null);
  }

  function currentUser() {
    var s = currentSession();
    if (!s) return null;
    var u = findById(s.userId);
    if (!u || u.status === 'suspended') {
      endSession();
      return null;
    }
    return u;
  }

  function touchSession() {
    var s = currentSession();
    if (s) {
      s.lastSeen = Date.now();
      write(KEYS.session, s);
    }
  }

  function endSession() {
    var u = currentUser();
    if (u) logActivity('Signed out', 'auth', {}, u.id);
    localStorage.removeItem(KEYS.session);
  }

  /* ---------- admin ---------- */

  function adminSignIn(username, password) {
    var cfg = window.XADON_CONFIG.admin;
    var override = read(KEYS.adminReset, null);
    var expected = override && override.password ? override.password : cfg.password;

    if (String(username).trim().toLowerCase() !== cfg.username.toLowerCase()) {
      return { ok: false, error: 'That is not the admin username.' };
    }
    if (!safeEqual(String(password), expected)) {
      return { ok: false, error: 'Wrong admin password.' };
    }
    write(KEYS.adminSession, { startedAt: Date.now(), agent: navigator.userAgent });
    logActivity('Admin console opened', 'admin', {}, 'admin');
    return { ok: true };
  }

  function adminActive() {
    return !!read(KEYS.adminSession, null);
  }

  function adminSignOut() {
    localStorage.removeItem(KEYS.adminSession);
  }

  /* Issues a one-time code. A real deployment mails this from the
     server; here it is shown on screen and pre-filled into a mail
     draft addressed to the recovery inbox. */
  function issueAdminResetCode() {
    var code = randomHex(3).toUpperCase();
    write(KEYS.adminReset, {
      code: code,
      issuedAt: Date.now(),
      expiresAt: Date.now() + 15 * 60 * 1000,
      password: read(KEYS.adminReset, {}).password || null
    });
    logActivity('Admin password reset requested', 'admin', { sentTo: window.XADON_CONFIG.admin.recoveryEmail }, 'admin');
    return code;
  }

  function completeAdminReset(code, newPassword) {
    var record = read(KEYS.adminReset, null);
    if (!record || !record.code) return { ok: false, error: 'Request a reset code first.' };
    if (Date.now() > record.expiresAt) return { ok: false, error: 'That code expired. Request a new one.' };
    if (!safeEqual(String(code).trim().toUpperCase(), record.code)) {
      return { ok: false, error: 'That code does not match the one we issued.' };
    }
    if (String(newPassword).length < 10) {
      return { ok: false, error: 'Use at least 10 characters for the admin password.' };
    }
    write(KEYS.adminReset, { password: newPassword, code: null, issuedAt: record.issuedAt, expiresAt: 0 });
    logActivity('Admin password changed', 'admin', {}, 'admin');
    return { ok: true };
  }

  /* ---------- activity log ---------- */

  function logActivity(action, category, meta, userIdOverride) {
    var user = userIdOverride ? null : currentUser();
    var entry = {
      id: uid('evt'),
      userId: userIdOverride || (user ? user.id : 'anonymous'),
      userName: userIdOverride === 'admin' ? 'Administrator' : user ? user.name : 'Signed out',
      action: action,
      category: category || 'system',
      meta: meta || {},
      at: Date.now(),
      path: location.pathname
    };
    var list = read(KEYS.activity, []);
    list.unshift(entry);
    /* Keep the log bounded so localStorage never fills up. */
    if (list.length > 600) list = list.slice(0, 600);
    write(KEYS.activity, list);
    document.dispatchEvent(new CustomEvent('xadon:activity', { detail: entry }));
    return entry;
  }

  function activity(filter) {
    var list = read(KEYS.activity, []);
    if (!filter) return list;
    return list.filter(function (e) {
      if (filter.userId && e.userId !== filter.userId) return false;
      if (filter.category && e.category !== filter.category) return false;
      return true;
    });
  }

  function clearActivity() {
    write(KEYS.activity, []);
  }

  /* ---------- preferences ---------- */

  function prefs() {
    return read(KEYS.prefs, {});
  }

  function setPref(key, value) {
    var p = prefs();
    p[key] = value;
    write(KEYS.prefs, p);
    return p;
  }

  /* ---------- encrypted vault ---------- */

  function vaultKey(passphrase, saltHex) {
    var enc = new TextEncoder();
    return crypto.subtle
      .importKey('raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey'])
      .then(function (base) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: ITERATIONS, hash: 'SHA-256' },
          base,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
      });
  }

  function vaultSave(passphrase, plaintext) {
    var salt = randomHex(16);
    var ivBytes = new Uint8Array(12);
    crypto.getRandomValues(ivBytes);
    return vaultKey(passphrase, salt)
      .then(function (key) {
        return crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: ivBytes },
          key,
          new TextEncoder().encode(plaintext)
        );
      })
      .then(function (cipher) {
        write(KEYS.vault, {
          salt: salt,
          iv: bytesToHex(ivBytes),
          data: bytesToHex(cipher),
          savedAt: Date.now()
        });
        return true;
      });
  }

  function vaultLoad(passphrase) {
    var record = read(KEYS.vault, null);
    if (!record) return Promise.reject(new Error('Nothing saved in the vault yet.'));
    return vaultKey(passphrase, record.salt)
      .then(function (key) {
        return crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: hexToBytes(record.iv) },
          key,
          hexToBytes(record.data)
        );
      })
      .then(function (plain) {
        return new TextDecoder().decode(plain);
      })
      .catch(function () {
        throw new Error('Wrong passphrase, or the stored data was changed.');
      });
  }

  function vaultExists() {
    return !!read(KEYS.vault, null);
  }

  function vaultClear() {
    localStorage.removeItem(KEYS.vault);
  }

  /* ---------- export ---------- */

  function exportAll() {
    return {
      exportedAt: new Date().toISOString(),
      product: window.XADON_CONFIG.product,
      version: window.XADON_CONFIG.version,
      users: allUsers().map(function (u) {
        var copy = Object.assign({}, u);
        delete copy.hash;
        delete copy.salt;
        return copy;
      }),
      activity: read(KEYS.activity, [])
    };
  }

  window.XadonStore = {
    KEYS: KEYS,
    uid: uid,
    randomHex: randomHex,
    bytesToHex: bytesToHex,
    allUsers: allUsers,
    findByEmail: findByEmail,
    findById: findById,
    createAccount: createAccount,
    verifyPassword: verifyPassword,
    updateUser: updateUser,
    deleteUser: deleteUser,
    startSession: startSession,
    currentUser: currentUser,
    currentSession: currentSession,
    touchSession: touchSession,
    endSession: endSession,
    adminSignIn: adminSignIn,
    adminActive: adminActive,
    adminSignOut: adminSignOut,
    issueAdminResetCode: issueAdminResetCode,
    completeAdminReset: completeAdminReset,
    logActivity: logActivity,
    activity: activity,
    clearActivity: clearActivity,
    prefs: prefs,
    setPref: setPref,
    vaultSave: vaultSave,
    vaultLoad: vaultLoad,
    vaultExists: vaultExists,
    vaultClear: vaultClear,
    exportAll: exportAll
  };
})();
