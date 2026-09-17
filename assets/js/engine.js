/* ============================================================
   Defense engine
   Everything in this file does real work in the browser. No
   placeholder results, no fake timers pretending to scan.

   What it can do:   inspect links and messages you paste in,
                     measure password strength, check a password
                     against the Have I Been Pwned breach corpus
                     without sending the password, hash files
                     locally, read genuine device and browser
                     posture signals, stream live telemetry.

   What it cannot do: reach into an arbitrary phone and scan its
                     files, or locate/lock/wipe a device. No web
                     page can. Those need an enrolled device and
                     an official provider (Android Management API,
                     Apple MDM). The UI says so where it matters.
   ============================================================ */

(function () {
  'use strict';

  /* ---------------------------------------------------------
     Reference data
     --------------------------------------------------------- */

  var BRANDS = [
    'google', 'gmail', 'facebook', 'instagram', 'whatsapp', 'tiktok', 'twitter',
    'apple', 'icloud', 'microsoft', 'outlook', 'netflix', 'amazon', 'paypal',
    'binance', 'coinbase', 'dhl', 'fedex', 'linkedin', 'telegram', 'youtube',
    'gtbank', 'zenithbank', 'accessbank', 'firstbank', 'ubagroup', 'uba',
    'opay', 'palmpay', 'kuda', 'moniepoint', 'interswitch', 'flutterwave',
    'paystack', 'quickteller', 'remita', 'nairaland', 'jumia', 'konga'
  ];

  var RISKY_TLDS = [
    'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click',
    'link', 'country', 'rest', 'cam', 'sbs', 'quest', 'buzz', 'lol', 'monster',
    'cyou', 'icu', 'bond', 'cfd'
  ];

  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'bl.ink', 'rebrand.ly',
    't.ly', 'shorte.st', 'adf.ly'
  ];

  var SENSITIVE_PATH_WORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'update', 'confirm',
    'account', 'wallet', 'billing', 'payment', 'invoice', 'otp', 'bvn', 'nin',
    'unlock', 'suspended', 'recover', 'password', 'authorize', 'validate'
  ];

  var EXECUTABLE_EXT = [
    'exe', 'apk', 'scr', 'bat', 'cmd', 'com', 'pif', 'msi', 'jar', 'vbs',
    'js', 'ps1', 'sh', 'dmg', 'iso', 'hta', 'lnk'
  ];

  /* ---------------------------------------------------------
     Small utilities
     --------------------------------------------------------- */

  function levenshtein(a, b) {
    if (a === b) return 0;
    var m = a.length, n = b.length;
    if (!m) return n;
    if (!n) return m;
    var prev = new Array(n + 1), cur = new Array(n + 1), i, j;
    for (j = 0; j <= n; j++) prev[j] = j;
    for (i = 1; i <= m; i++) {
      cur[0] = i;
      for (j = 1; j <= n; j++) {
        cur[j] = Math.min(
          prev[j] + 1,
          cur[j - 1] + 1,
          prev[j - 1] + (a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1)
        );
      }
      for (j = 0; j <= n; j++) prev[j] = cur[j];
    }
    return prev[n];
  }

  function isIpLiteral(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[[0-9a-f:]+\]$/i.test(host);
  }

  /* Registrable-ish domain. Handles common two-part public suffixes
     (co.uk, com.ng, org.ng...) which matter a lot for spotting
     "gtbank.com.ng.secure-login.xyz" style abuse. */
  var TWO_PART_SUFFIX = /\.(co|com|org|net|gov|edu|ac|mil|sch|ngo)\.[a-z]{2,3}$/i;

  function registrableDomain(host) {
    var parts = host.split('.');
    if (parts.length < 3) return host;
    return TWO_PART_SUFFIX.test(host) ? parts.slice(-3).join('.') : parts.slice(-2).join('.');
  }

  function hasMixedScript(text) {
    var latin = /[a-z]/i.test(text);
    var cyrillic = /[\u0400-\u04FF]/.test(text);
    var greek = /[\u0370-\u03FF]/.test(text);
    var other = /[\u0500-\u1FFF\u2C00-\uD7FF]/.test(text);
    return latin && (cyrillic || greek || other);
  }

  /* ---------------------------------------------------------
     Link inspector
     --------------------------------------------------------- */

  function analyzeUrl(raw) {
    var input = String(raw || '').trim();
    var findings = [];
    var score = 0;

    function flag(weight, severity, title, detail) {
      findings.push({ severity: severity, title: title, detail: detail });
      score += weight;
    }

    if (!input) {
      return { ok: false, error: 'Paste a link first.' };
    }

    if (/^javascript:/i.test(input)) {
      flag(60, 'high', 'This is a javascript: link',
        'It runs code instead of opening a page. This is the classic "paste this in your browser" account-takeover trick. Do not run it.');
    }
    if (/^data:/i.test(input)) {
      flag(50, 'high', 'This is a data: link',
        'The whole page is embedded in the link itself, so there is no real website behind it. Phishing kits use this to dodge domain blocklists.');
    }

    var url;
    var candidate = /^[a-z][a-z0-9+.-]*:/i.test(input) ? input : 'http://' + input;
    try {
      url = new URL(candidate);
    } catch (err) {
      return {
        ok: true,
        input: input,
        verdict: 'unreadable',
        score: 0,
        findings: [{
          severity: 'medium',
          title: 'That is not a valid web address',
          detail: 'Nothing here parses as a URL. If it came from a message, treat it as suspicious rather than mistyped.'
        }],
        parts: null
      };
    }

    var host = url.hostname.toLowerCase();
    var domain = registrableDomain(host);
    var tld = host.split('.').pop();
    var pathAndQuery = (url.pathname + url.search).toLowerCase();

    /* transport */
    if (url.protocol === 'http:') {
      flag(18, 'medium', 'No encryption (http, not https)',
        'Anything you type on this page — passwords, card numbers, OTPs — travels in the clear and can be read on the network.');
    }

    /* credentials in the authority section */
    if (url.username || url.password) {
      flag(45, 'high', 'Login details are hidden in the link itself',
        'Everything before the @ sign is ignored by the browser. The real destination is ' + host + ', not what you see at the start.');
    }

    /* raw IP */
    if (isIpLiteral(host)) {
      flag(35, 'high', 'Points at a bare IP address',
        'Real services use names, not raw IPs. This is typical of a temporary server set up for a campaign.');
    }

    /* punycode / homoglyph */
    if (host.indexOf('xn--') !== -1) {
      flag(40, 'high', 'The domain uses punycode',
        'Non-Latin characters can be drawn to look exactly like ordinary letters. The name you read may not be the name your browser resolves.');
    }
    if (hasMixedScript(host)) {
      flag(40, 'high', 'The domain mixes alphabets',
        'Latin letters are combined with another script. This is a deliberate look-alike technique.');
    }

    /* shorteners */
    if (SHORTENERS.indexOf(domain) !== -1) {
      flag(22, 'medium', 'Shortened link hides the destination',
        'You cannot tell where ' + domain + ' will send you until you are already there. Expand it first, or ask the sender for the full address.');
    }

    /* suspicious TLD */
    if (RISKY_TLDS.indexOf(tld) !== -1) {
      flag(16, 'medium', 'Ends in .' + tld + ', a high-abuse ending',
        'These endings are cheap or free to register, so they turn up far more often in phishing than in legitimate business.');
    }

    /* subdomain depth */
    var labels = host.split('.').length;
    if (labels >= 5) {
      flag(18, 'medium', 'Unusually deep subdomain chain',
        host + ' has ' + labels + ' parts. Long chains are used to push a trusted-looking word to the front where you will read it first.');
    }

    /* brand abuse: brand appears somewhere but does not own the domain */
    var brandHit = null;
    for (var i = 0; i < BRANDS.length; i++) {
      var brand = BRANDS[i];
      var inHost = host.indexOf(brand) !== -1;
      var ownsDomain = domain.indexOf(brand + '.') === 0 || domain === brand;
      if (inHost && !ownsDomain) { brandHit = brand; break; }
    }
    if (brandHit) {
      flag(42, 'high', 'Uses the name "' + brandHit + '" without owning the domain',
        'The registered domain here is ' + domain + '. Only the part immediately before the ending decides who controls the site — everything else is decoration.');
    }

    /* look-alike typo domain */
    if (!brandHit) {
      var core = domain.split('.')[0];
      for (var k = 0; k < BRANDS.length; k++) {
        var b = BRANDS[k];
        if (core === b) break;
        if (Math.abs(core.length - b.length) <= 2 && core.length > 4) {
          var d = levenshtein(core, b);
          if (d > 0 && d <= 2) {
            flag(38, 'high', 'One or two letters away from "' + b + '"',
              core + ' is close enough to ' + b + ' to be missed at a glance. Check the spelling character by character.');
            break;
          }
        }
      }
    }

    /* hyphen padding */
    var hyphens = (host.match(/-/g) || []).length;
    if (hyphens >= 3) {
      flag(14, 'medium', 'Domain is padded with hyphens',
        hyphens + ' hyphens in one name is a common way to stuff reassuring words like "secure" or "verify" into an address.');
    }

    /* non-standard port */
    if (url.port && url.port !== '80' && url.port !== '443') {
      flag(20, 'medium', 'Serves from an unusual port (' + url.port + ')',
        'Public websites almost never do this. It often signals a hastily deployed server.');
    }

    /* sensitive words in path */
    var pathWords = SENSITIVE_PATH_WORDS.filter(function (w) {
      return pathAndQuery.indexOf(w) !== -1;
    });
    if (pathWords.length >= 2) {
      flag(20, 'medium', 'The path is built around credential words',
        'It contains: ' + pathWords.slice(0, 4).join(', ') + '. Combined with anything else on this list, treat the page as a credential trap.');
    } else if (pathWords.length === 1) {
      flag(8, 'low', 'The path mentions "' + pathWords[0] + '"',
        'Normal on a real login page. Worth a second look when it arrives in an unexpected message.');
    }

    /* double extension / executable download */
    var fileMatch = url.pathname.toLowerCase().match(/\.([a-z0-9]{2,4})$/);
    if (fileMatch && EXECUTABLE_EXT.indexOf(fileMatch[1]) !== -1) {
      flag(35, 'high', 'Links straight to a .' + fileMatch[1] + ' file',
        'This downloads something that runs, rather than a page you read. Only install software from the official store or vendor site.');
    }
    if (/\.(pdf|doc|docx|jpg|png|xls|xlsx)\.[a-z0-9]{2,4}$/i.test(url.pathname)) {
      flag(40, 'high', 'Double file extension',
        'The name is dressed up as a document but the real extension is the last one. This is a standard malware disguise.');
    }

    /* length */
    if (input.length > 140) {
      flag(10, 'low', 'Very long link (' + input.length + ' characters)',
        'Length alone is not dangerous, but it makes the real destination hard to read, which is often the point.');
    }

    /* encoded payload */
    if (/%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}/i.test(input)) {
      flag(15, 'medium', 'Heavily percent-encoded',
        'Encoding is normal in small amounts. Long encoded runs are used to hide keywords from filters.');
    }
    if (/[?&](redirect|url|next|continue|return|goto|dest)=https?%3a/i.test(input)) {
      flag(25, 'medium', 'Carries a redirect to another site',
        'The address you see is only the first hop. An open redirect on a trusted domain is a favourite way to borrow its reputation.');
    }

    /* good signs, only when nothing serious fired */
    if (score === 0) {
      findings.push({
        severity: 'clear',
        title: 'No known warning patterns',
        detail: 'Encrypted transport, a plain readable domain, and nothing in the address designed to mislead.'
      });
    }

    var verdict = score >= 45 ? 'high' : score >= 18 ? 'caution' : 'clear';

    return {
      ok: true,
      input: input,
      verdict: verdict,
      score: Math.min(100, score),
      findings: findings.sort(function (a, b) {
        var order = { high: 0, medium: 1, low: 2, clear: 3 };
        return order[a.severity] - order[b.severity];
      }),
      parts: {
        scheme: url.protocol.replace(':', ''),
        host: host,
        domain: domain,
        path: url.pathname || '/',
        query: url.search || '(none)'
      }
    };
  }

  /* ---------------------------------------------------------
     Message inspector — SMS, email, WhatsApp
     --------------------------------------------------------- */

  var MESSAGE_RULES = [
    { weight: 30, test: /\b(otp|one[- ]time (pin|code|password)|verification code)\b/i,
      title: 'Asks about a one-time code',
      detail: 'No bank, app or support desk ever needs your OTP. Anyone asking for one is trying to finish a login as you.' },
    { weight: 32, test: /\b(bvn|nin|atm pin|card pin|cvv|account number and pin)\b/i,
      title: 'Asks for an identity or card secret',
      detail: 'BVN, NIN, PIN and CVV are never collected over chat or SMS. Stop here.' },
    { weight: 22, test: /\b(suspend(ed)?|deactivat|block(ed)?|restrict(ed)?|closure|expire[sd]?)\b.{0,40}\b(account|card|wallet|bvn|sim)\b/i,
      title: 'Threatens your account',
      detail: 'Manufactured fear is the engine of phishing. Real institutions do not give you minutes to act.' },
    { weight: 20, test: /\b(within|in) (the next )?(\d+|a few) ?(minute|hour|hrs|min)s?\b|\b(immediately|urgent(ly)?|right now|today only|last warning)\b/i,
      title: 'Manufactured urgency',
      detail: 'Pressure exists to stop you checking. Slow down; the deadline is not real.' },
    { weight: 26, test: /\b(you(\s|')?ve won|congratulations|lucky winner|claim your (prize|reward)|selected winner|giveaway)\b/i,
      title: 'Prize or giveaway claim',
      detail: 'You cannot win a draw you never entered. The prize is bait for a "processing fee" or your card details.' },
    { weight: 24, test: /\b(roi|double your|guaranteed (profit|return)|invest(ment)? plan|forex signal|mining|usdt|crypto ?(wallet|trade))\b/i,
      title: 'Investment or crypto pitch',
      detail: 'Guaranteed returns do not exist. Claims of fixed daily profit describe a ponzi structure.' },
    { weight: 22, test: /\b(customs|delivery|parcel|package|shipment|courier)\b.{0,50}\b(fee|charge|pay|clear|held|pending)\b/i,
      title: 'Delivery fee demand',
      detail: 'Couriers bill the sender or collect at the door, not through a link in an SMS.' },
    { weight: 20, test: /\b(this is my new number|lost my phone|new line|save this number)\b/i,
      title: 'Claims to be someone you know on a new number',
      detail: 'The family-impersonation scam. Call the person on their old number before you reply to anything.' },
    { weight: 18, test: /\b(gift ?card|steam card|itunes card|google play card|recharge card pin)\b/i,
      title: 'Asks for gift card codes',
      detail: 'Gift cards are untraceable, which is exactly why fraud uses them. No legitimate payment works this way.' },
    { weight: 16, test: /\b(work from home|earn .{0,12}(daily|weekly)|no experience needed|part[- ]time job).{0,60}\b(register|pay|fee|whatsapp)\b/i,
      title: 'Job offer that asks you to pay',
      detail: 'A real employer pays you. Registration and training fees are the scam itself.' },
    { weight: 14, test: /\bdear (customer|user|valued|account holder|sir\/ma)\b/i,
      title: 'Generic greeting',
      detail: 'Your bank knows your name. Bulk greetings mean bulk sending.' },
    { weight: 14, test: /\b(kindly|please) (click|tap|open|follow) (the |this )?link\b|\bclick (here|below)\b/i,
      title: 'Pushes you to a link',
      detail: 'Type the address yourself or use the official app. Never navigate from an unexpected message.' },
    { weight: 12, test: /\b(don'?t tell|keep this (between us|confidential|private)|secret)\b/i,
      title: 'Asks you to keep it quiet',
      detail: 'Isolation is a control tactic. Tell someone you trust before you act.' },
    { weight: 18, test: /\b(anydesk|teamviewer|quicksupport|remote (access|desktop)|screen ?share)\b/i,
      title: 'Wants remote access to your device',
      detail: 'Installing this hands over full control. Support desks you called yourself are the only exception.' }
  ];

  function analyzeMessage(raw) {
    var text = String(raw || '').trim();
    if (!text) return { ok: false, error: 'Paste the message first.' };

    var findings = [];
    var score = 0;

    MESSAGE_RULES.forEach(function (rule) {
      if (rule.test.test(text)) {
        score += rule.weight;
        findings.push({ severity: rule.weight >= 24 ? 'high' : rule.weight >= 16 ? 'medium' : 'low',
          title: rule.title, detail: rule.detail });
      }
    });

    /* links inside the message get the full link inspection */
    var urlMatches = text.match(/((https?:\/\/|www\.)[^\s<>"']+)/gi) || [];
    var linkReports = urlMatches.slice(0, 5).map(function (u) {
      return analyzeUrl(u);
    });
    linkReports.forEach(function (report) {
      if (report.verdict === 'high') score += 30;
      else if (report.verdict === 'caution') score += 12;
    });

    /* shouting */
    var letters = text.replace(/[^A-Za-z]/g, '');
    if (letters.length > 25) {
      var caps = (text.match(/[A-Z]/g) || []).length / letters.length;
      if (caps > 0.5) {
        score += 10;
        findings.push({ severity: 'low', title: 'Mostly capital letters',
          detail: 'Shouting is used to force attention. Legitimate notices are written normally.' });
      }
    }

    /* naira / dollar amounts alongside a payment instruction */
    var hasAmount = /(₦|\$|£|€)\s?[\d,]{3,}/.test(text)
      || /\b(ngn|usd|naira|dollars?)\s?[\d,]{3,}/i.test(text)
      || /\bn\s?[\d,]{3,}\b/i.test(text);
    if (hasAmount && /\b(pay|send|transfer|deposit|fee|charge|claim)\b/i.test(text)) {
      score += 16;
      findings.push({ severity: 'medium', title: 'Names an amount and asks you to send it',
        detail: 'Confirm through a channel you started yourself before any money moves.' });
    }

    if (!findings.length && !linkReports.length) {
      findings.push({ severity: 'clear', title: 'No scam patterns matched',
        detail: 'Nothing here matches a known fraud template. Pattern matching is not proof — if the request involves money or codes, verify it separately.' });
    }

    var verdict = score >= 45 ? 'high' : score >= 18 ? 'caution' : 'clear';
    return { ok: true, verdict: verdict, score: Math.min(100, score), findings: findings, links: linkReports };
  }

  /* ---------------------------------------------------------
     Password strength + breach lookup
     --------------------------------------------------------- */

  var COMMON = ['password', '123456', 'qwerty', 'letmein', 'welcome', 'admin',
    'iloveyou', 'monkey', 'dragon', 'football', 'abc123', 'passw0rd', 'god',
    'jesus', 'naija', 'chelsea', 'arsenal', 'sunshine', 'princess'];

  function scorePassword(pw) {
    var value = String(pw || '');
    if (!value) return { score: 0, label: 'Empty', entropy: 0, advice: 'Enter a password.', notes: [] };

    var pool = 0;
    if (/[a-z]/.test(value)) pool += 26;
    if (/[A-Z]/.test(value)) pool += 26;
    if (/[0-9]/.test(value)) pool += 10;
    if (/[^A-Za-z0-9]/.test(value)) pool += 33;
    var entropy = value.length * (Math.log(pool || 1) / Math.log(2));

    var notes = [];
    var penalty = 0;

    /* Fold common character substitutions before the dictionary check.
       "P@ssw0rd" and "password" are the same word to a cracking tool,
       so they should be the same word to us. */
    var lower = value.toLowerCase();
    var folded = lower
      .replace(/[@4]/g, 'a').replace(/[3]/g, 'e').replace(/[1!|]/g, 'i')
      .replace(/[0]/g, 'o').replace(/[5$]/g, 's').replace(/[7]/g, 't');

    COMMON.forEach(function (word) {
      if (lower.indexOf(word) !== -1 || folded.indexOf(word) !== -1) {
        penalty += 26;
        notes.push('Contains the common word "' + word + '", including after swapping letters for lookalike digits.');
      }
    });
    if (/(.)\1{2,}/.test(value)) { penalty += 10; notes.push('Has a character repeated three or more times.'); }
    if (/^(19|20)\d{2}/.test(value) || /(19|20)\d{2}$/.test(value)) { penalty += 10; notes.push('Contains a year, which is easy to guess.'); }
    if (/^[a-z]+\d{1,4}$/i.test(value)) { penalty += 14; notes.push('Word-then-digits is the first pattern cracking tools try.'); }
    if (/(abc|qwe|asd|zxc|123|987)/i.test(value)) { penalty += 12; notes.push('Contains a keyboard or counting sequence.'); }
    if (value.length < 12) { penalty += (12 - value.length) * 3; notes.push('Shorter than 12 characters.'); }

    var effective = Math.max(0, entropy - penalty);
    var score = effective >= 75 ? 4 : effective >= 55 ? 3 : effective >= 38 ? 2 : effective >= 22 ? 1 : 0;
    var labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
    var advice = score >= 3
      ? 'Good. Store it in a password manager and never reuse it.'
      : 'Use four or more unrelated words, or let the generator below build one.';

    return {
      score: score,
      label: labels[score],
      entropy: Math.round(effective),
      rawEntropy: Math.round(entropy),
      advice: advice,
      notes: notes
    };
  }

  function sha1Hex(text) {
    return crypto.subtle
      .digest('SHA-1', new TextEncoder().encode(text))
      .then(function (buf) {
        return Array.prototype.map
          .call(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, '0'); })
          .join('')
          .toUpperCase();
      });
  }

  /* k-anonymity: only the first five hash characters are sent.
     The service cannot learn the password, and neither can anyone
     watching the request. */
  function breachCheck(password) {
    if (!window.XADON_CONFIG.breachLookup) {
      return Promise.resolve({ available: false, reason: 'Breach lookup is switched off in config.js.' });
    }
    return sha1Hex(password).then(function (hash) {
      var prefix = hash.slice(0, 5);
      var suffix = hash.slice(5);
      return fetch('https://api.pwnedpasswords.com/range/' + prefix, {
        headers: { 'Add-Padding': 'true' }
      })
        .then(function (res) {
          if (!res.ok) throw new Error('lookup failed');
          return res.text();
        })
        .then(function (body) {
          var count = 0;
          body.split('\n').forEach(function (line) {
            var pair = line.trim().split(':');
            if (pair[0] === suffix) count = parseInt(pair[1], 10) || 0;
          });
          return { available: true, count: count, prefixSent: prefix };
        })
        .catch(function () {
          return { available: false, reason: 'Could not reach the breach database. Check your connection.' };
        });
    });
  }

  function generatePassphrase(words) {
    var list = ['harbour', 'copper', 'lantern', 'thunder', 'cassava', 'orbit', 'marble',
      'pelican', 'kettle', 'granite', 'velvet', 'mango', 'cedar', 'anchor', 'saffron',
      'willow', 'quartz', 'falcon', 'ember', 'basalt', 'tundra', 'ivory', 'cobalt',
      'juniper', 'nimbus', 'onyx', 'papyrus', 'ridge', 'sable', 'talon'];
    var count = words || 4;
    var picks = [];
    var buf = new Uint32Array(count);
    crypto.getRandomValues(buf);
    for (var i = 0; i < count; i++) picks.push(list[buf[i] % list.length]);
    var digits = new Uint32Array(1);
    crypto.getRandomValues(digits);
    return picks.join('-') + '-' + (digits[0] % 90 + 10);
  }

  function generatePassword(length) {
    var alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+';
    var size = length || 20;
    var buf = new Uint32Array(size);
    crypto.getRandomValues(buf);
    var out = '';
    for (var i = 0; i < size; i++) out += alphabet[buf[i] % alphabet.length];
    return out;
  }

  /* ---------------------------------------------------------
     File hashing — runs entirely on your machine
     --------------------------------------------------------- */

  function hashFile(file, onProgress) {
    return new Promise(function (resolve, reject) {
      if (file.size > 250 * 1024 * 1024) {
        reject(new Error('That file is larger than 250 MB. Hash it with a desktop tool instead.'));
        return;
      }
      var reader = new FileReader();
      reader.onprogress = function (e) {
        if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100));
      };
      reader.onerror = function () { reject(new Error('Could not read that file.')); };
      reader.onload = function () {
        var buffer = reader.result;
        Promise.all([
          crypto.subtle.digest('SHA-256', buffer),
          crypto.subtle.digest('SHA-1', buffer)
        ]).then(function (digests) {
          function hex(d) {
            return Array.prototype.map
              .call(new Uint8Array(d), function (b) { return b.toString(16).padStart(2, '0'); })
              .join('');
          }
          var name = file.name.toLowerCase();
          var ext = (name.match(/\.([a-z0-9]{1,5})$/) || [, ''])[1];
          var warnings = [];
          if (EXECUTABLE_EXT.indexOf(ext) !== -1) {
            warnings.push('.' + ext + ' files run code when opened. Only install from the official store or the vendor site.');
          }
          if (/\.(pdf|doc|docx|jpg|png|xls|xlsx)\.[a-z0-9]{2,4}$/i.test(name)) {
            warnings.push('This filename has two extensions. The last one is what actually runs.');
          }
          resolve({
            name: file.name,
            size: file.size,
            type: file.type || 'unknown',
            sha256: hex(digests[0]),
            sha1: hex(digests[1]),
            warnings: warnings
          });
        }).catch(reject);
      };
      reader.readAsArrayBuffer(file);
    });
  }

  /* ---------------------------------------------------------
     Device posture — genuine signals from this browser
     --------------------------------------------------------- */

  function devicePosture() {
    var checks = [];

    function add(id, label, state, detail, fix, weight) {
      checks.push({ id: id, label: label, state: state, detail: detail, fix: fix || '', weight: weight || 1 });
    }

    /* transport */
    if (window.isSecureContext) {
      add('tls', 'Encrypted connection', 'pass',
        'This page was loaded over HTTPS, so traffic between you and the server is encrypted.', '', 3);
    } else {
      add('tls', 'Encrypted connection', 'fail',
        'This page is not in a secure context. Passwords typed here can be read on the network.',
        'Open the site over https:// and enable HTTPS-only mode in your browser settings.', 3);
    }

    /* crypto availability */
    add('webcrypto', 'Strong crypto available',
      window.crypto && window.crypto.subtle ? 'pass' : 'fail',
      window.crypto && window.crypto.subtle
        ? 'The browser exposes Web Crypto, so hashing and the encrypted vault work locally.'
        : 'Web Crypto is missing. Password hashing and the vault cannot run.',
      'Update your browser to a current version.', 2);

    /* automation */
    if (navigator.webdriver) {
      add('automation', 'Automation detected', 'warn',
        'This browser reports that it is being driven by software rather than a person.',
        'If you did not start an automation tool, close it and scan the machine.', 2);
    } else {
      add('automation', 'No automation detected', 'pass',
        'The browser is not reporting remote control.', '', 2);
    }

    /* storage */
    add('storage', 'Local storage usable', typeof localStorage !== 'undefined' ? 'pass' : 'fail',
      typeof localStorage !== 'undefined'
        ? 'Settings and the encrypted vault can be saved on this device.'
        : 'Storage is blocked, so nothing will persist between visits.',
      'Allow site data for this origin, or leave private browsing.', 1);

    /* cookies */
    add('cookies', 'Cookies enabled', navigator.cookieEnabled ? 'pass' : 'warn',
      navigator.cookieEnabled
        ? 'Sessions can be maintained normally.'
        : 'Cookies are blocked. Some sign-in flows, including Google, will not complete.',
      'Allow cookies for this site.', 1);

    /* tracking preference */
    var gpc = navigator.globalPrivacyControl === true;
    var dnt = navigator.doNotTrack === '1' || window.doNotTrack === '1';
    add('tracking', 'Tracking preference signalled', gpc || dnt ? 'pass' : 'info',
      gpc || dnt
        ? 'Your browser is telling sites not to sell or share your data' + (gpc ? ' (Global Privacy Control).' : ' (Do Not Track).')
        : 'No opt-out signal is being sent. Sites you visit see no preference.',
      'Turn on Global Privacy Control in your browser privacy settings.', 1);

    /* connection */
    var conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (conn) {
      add('network', 'Network type', 'info',
        'Reported as ' + (conn.effectiveType || 'unknown') +
        (conn.saveData ? ', data saver on' : '') + '.',
        'On public Wi-Fi, avoid signing in to banking without a VPN.', 1);
    }

    /* memory / cores — weak device signal */
    if (navigator.deviceMemory && navigator.deviceMemory <= 2) {
      add('hardware', 'Low-memory device', 'info',
        'Around ' + navigator.deviceMemory + " GB reported. Security software can struggle on devices this size.", '', 1);
    }

    /* timezone vs language mismatch — possible proxy or spoofing */
    try {
      var tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      var lang = (navigator.language || '').toLowerCase();
      add('locale', 'Locale consistency', 'info',
        'Time zone ' + tz + ', language ' + (lang || 'unknown') + '.',
        'A mismatch is normal when travelling or using a VPN. Unexpected mismatches are worth a look.', 1);
    } catch (e) { /* ignore */ }

    return checks;
  }

  function permissionAudit() {
    var names = ['geolocation', 'notifications', 'camera', 'microphone', 'clipboard-read', 'persistent-storage'];
    if (!navigator.permissions || !navigator.permissions.query) {
      return Promise.resolve([{ name: 'permissions', state: 'unsupported',
        note: 'This browser does not expose the Permissions API.' }]);
    }
    return Promise.all(names.map(function (name) {
      return navigator.permissions
        .query({ name: name })
        .then(function (status) { return { name: name, state: status.state }; })
        .catch(function () { return { name: name, state: 'unsupported' }; });
    }));
  }

  function storageEstimate() {
    if (!navigator.storage || !navigator.storage.estimate) return Promise.resolve(null);
    return navigator.storage.estimate().catch(function () { return null; });
  }

  function postureScore(checks) {
    var total = 0, earned = 0;
    checks.forEach(function (c) {
      if (c.state === 'info') return;
      total += c.weight;
      if (c.state === 'pass') earned += c.weight;
      else if (c.state === 'warn') earned += c.weight * 0.5;
    });
    return total ? Math.round((earned / total) * 100) : 100;
  }

  /* ---------------------------------------------------------
     Live telemetry — real browser events, not a fake ticker
     --------------------------------------------------------- */

  var listeners = [];
  var started = false;

  function emit(signal) {
    document.dispatchEvent(new CustomEvent('xadon:signal', { detail: signal }));
  }

  function signal(tone, title, detail) {
    return { tone: tone, title: title, detail: detail, at: Date.now() };
  }

  function startTelemetry() {
    if (started) return;
    started = true;

    function on(target, type, handler) {
      target.addEventListener(type, handler);
      listeners.push(function () { target.removeEventListener(type, handler); });
    }

    on(window, 'online', function () {
      emit(signal('clear', 'Network restored', 'The device is back online. Signal collection resumed.'));
    });
    on(window, 'offline', function () {
      emit(signal('alert', 'Network lost', 'The device went offline. Live checks are paused until it returns.'));
    });

    on(document, 'visibilitychange', function () {
      emit(signal('info',
        document.hidden ? 'Console moved to the background' : 'Console back in focus',
        document.hidden ? 'Monitoring continues, but the browser may throttle timers.' : 'Full-rate monitoring resumed.'));
    });

    var conn = navigator.connection;
    if (conn && conn.addEventListener) {
      on(conn, 'change', function () {
        emit(signal('info', 'Network changed',
          'Now on ' + (conn.effectiveType || 'an unknown connection') +
          '. Re-check any session you started on the previous network.'));
      });
    }

    if (navigator.getBattery) {
      navigator.getBattery().then(function (battery) {
        on(battery, 'levelchange', function () {
          var pct = Math.round(battery.level * 100);
          if (pct <= 15 && !battery.charging) {
            emit(signal('warn', 'Battery low (' + pct + '%)',
              'If this device is lost while flat, remote location stops working. Charge it before you travel.'));
          }
        });
        on(battery, 'chargingchange', function () {
          if (battery.charging) {
            emit(signal('info', 'Charging started',
              'Avoid unknown public USB ports — use a wall socket or a data-blocker cable.'));
          }
        });
      }).catch(function () { /* battery API unavailable */ });
    }

    if (navigator.permissions && navigator.permissions.query) {
      ['geolocation', 'camera', 'microphone'].forEach(function (name) {
        navigator.permissions.query({ name: name }).then(function (status) {
          on(status, 'change', function () {
            emit(signal(status.state === 'granted' ? 'warn' : 'clear',
              'Permission changed: ' + name,
              'Now "' + status.state + '" for this site. Review which sites hold this permission if you did not expect the change.'));
          });
        }).catch(function () { /* unsupported */ });
      });
    }
  }

  function stopTelemetry() {
    listeners.forEach(function (off) { off(); });
    listeners = [];
    started = false;
  }

  /* ---------------------------------------------------------
     Exports
     --------------------------------------------------------- */

  window.XadonEngine = {
    analyzeUrl: analyzeUrl,
    analyzeMessage: analyzeMessage,
    scorePassword: scorePassword,
    breachCheck: breachCheck,
    generatePassword: generatePassword,
    generatePassphrase: generatePassphrase,
    hashFile: hashFile,
    devicePosture: devicePosture,
    permissionAudit: permissionAudit,
    storageEstimate: storageEstimate,
    postureScore: postureScore,
    startTelemetry: startTelemetry,
    stopTelemetry: stopTelemetry,
    levenshtein: levenshtein
  };
})();
