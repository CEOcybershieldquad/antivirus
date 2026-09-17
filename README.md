# XADON Phone Defense

A security console for people who handle their own risk. Paste in a link, a text message,
a password or a file and get a real answer with the reasoning shown.

Built by **Musteqeem** — [github.com/musteqeem](https://github.com/musteqeem)

---

## What actually works

Everything in this list does real work in your browser. Nothing is a mock-up.

| Tool | What it does | Where the work happens |
|---|---|---|
| Link inspector | 18 checks: punycode, mixed alphabets, look-alike domains (edit distance against 39 brands), credentials before an `@`, raw IPs, shorteners, high-abuse TLDs, subdomain depth, odd ports, credential words in the path, double extensions, open redirects | Your device |
| Message inspector | 14 fraud patterns tuned for SMS and WhatsApp, plus full link inspection on any URL inside | Your device |
| Password check | Entropy scoring with penalties for the patterns cracking tools try first, including leetspeak folding | Your device |
| Breach lookup | Have I Been Pwned range API using k-anonymity | Only the first 5 characters of a SHA-1 hash leave the device |
| File fingerprint | SHA-256 and SHA-1 via Web Crypto, with a VirusTotal hash lookup | Your device — the file is never uploaded |
| Device posture | 9 live browser signals, weighted into a score, each with the fix | Your device |
| Vault | AES-GCM, key derived with PBKDF2-SHA256 at 210,000 rounds | Your device |
| Incident playbook | 7 ordered steps for a lost or stolen phone, linking to the real Google/Apple controls | Your device |

## What it cannot do

Said plainly, because a lot of products in this space are not honest about it.

- **It cannot scan another phone's files.** A web page has no file system access. Real device
  scanning needs an installed app with OS-level permissions.
- **It cannot locate, lock or wipe a phone.** That requires enrolment with Google, Apple or an
  MDM provider. The incident playbook links to the genuine controls instead of faking a button.
- **It cannot block calls or read texts.** Browsers have no telephony access.
- **It cannot prove a site is safe.** Pattern analysis improves your odds. It does not remove risk.

---

## Deploying to Vercel

The entry point is `index.html` at the project root, exactly as Vercel expects.

```bash
npx vercel --prod
```

Or drag the folder into the Vercel dashboard. There is no build step and no dependencies.

`vercel.json` does two things: rewrites app routes to `index.html` so deep links like
`/console/links` work on refresh, and sets security headers including a content security
policy scoped to the three outbound hosts this app uses.

---

## Configuration

Everything configurable lives in `assets/js/config.js`.

### Google sign-in

Off until you add a Client ID. Until then the Google button explains the setup instead of
failing silently.

1. [console.cloud.google.com](https://console.cloud.google.com) → APIs & Services → Credentials
2. Create an **OAuth 2.0 Client ID**, application type **Web application**
3. Under *Authorised JavaScript origins* add `https://your-app.vercel.app`
   (leave redirect URIs empty — this uses Google Identity Services, not a redirect flow)
4. Paste the ID into `googleClientId` and redeploy

### Admin console

Reachable at `/admin`.

```
username: admin
password: adminxadon123
```

Forgot it? The sign-in page issues a six-character reset code valid for 15 minutes and opens
a pre-filled mail draft to `officialxadonai@gmail.com`. A static site has no mail server, so
you send that draft yourself — wire up Resend, Postmark or SES in a serverless function to
make it automatic.

The admin console shows every registered account, sign-in counts, last-seen times, a
per-account activity drill-down, and a live filterable monitor of everything everyone does,
exportable as CSV or JSON.

---

## Read this before you take real customers

**The security tools are real. The account system is a blueprint.**

Passwords are hashed with PBKDF2-SHA256 at 210,000 iterations with a random 16-byte salt —
the correct algorithm, following current OWASP guidance. But it runs in the browser, and a
browser cannot keep a secret. The same applies to the admin password, which sits in
`config.js` where anyone who opens DevTools can read it.

That is fine for a demo, a portfolio piece or an internal preview. It is not fine once real
people trust it with real accounts. In priority order:

1. **Move authentication to a server.** Every function in `store.js` maps one-to-one onto an
   API endpoint. `createAccount` → `POST /api/register`, `verifyPassword` → `POST /api/login`,
   and so on. Keep the same PBKDF2 parameters; just run them somewhere the user cannot reach.
2. **Verify the Google token server-side.** `auth.js` decodes the JWT to read the email, which
   proves it parses, not that it is genuine. Send `response.credential` to your backend and
   verify the signature against Google's public keys.
3. **Replace the admin gate** with real server-side auth and a role check.
4. **Connect a mail service** so reset codes send on their own.
5. **Keep the CSP tight.** Add hosts to `connect-src` in `vercel.json` only as you need them.

---

## Project layout

```
index.html              entry point — Vercel serves this
vercel.json             rewrites + security headers
assets/
  icon.svg
  css/style.css         design tokens and every component
  js/
    config.js           all configuration
    engine.js           the analysis engine — no DOM, fully testable
    store.js            accounts, sessions, activity log, vault
    ui.js               escaping, toasts, modals, formatting
    auth.js             sign up / sign in / Google / admin portal
    pages.js            defender console pages
    admin.js            admin console pages
    app.js              router and shell
```

`engine.js` has no DOM dependencies, so you can test it directly in Node.

---

## Changes from v4

The v4 sidebar linked to 11 pages but the router only handled 5 — Analytics, Policies,
Antivirus, Audit Log and Billing all silently fell through to the dashboard. That was the
main reason "some features are not working". Routes and navigation are now generated from
one table, so they cannot drift apart again.

Also fixed:

- `escapeHtml` was applied inconsistently, so a display name containing markup could inject
  into the audit log and the event stream. One escaping helper is now used everywhere.
- The report export contained a double-escaped `\\n`, producing literal `\n` in the file.
- `URL.revokeObjectURL` was called synchronously after `click()`, which can cancel the
  download in some browsers.
- `state.user.slice(0, 2)` threw when the stored username was empty.
- The 12-second event interval was never cleared and kept running after sign-out.
- The "realtime" event stream invented events on a timer. It now reports genuine browser
  events: network drops, permission changes, low battery, connection type changes.
- Unknown routes showed the dashboard. They now say the page does not exist.

## Licence

Do what you like with it. Attribution to Musteqeem is appreciated, not required.
