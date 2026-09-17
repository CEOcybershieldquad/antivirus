/* ============================================================
   XADON Phone Defense — configuration
   Edit this file to connect real providers. Nothing else needs
   to change.
   ============================================================ */

window.XADON_CONFIG = {
  product: 'XADON Phone Defense',
  creator: 'Musteqeem',
  githubUser: 'musteqeem',
  supportEmail: 'officialxadonai@gmail.com',

  /* ----------------------------------------------------------
     GOOGLE SIGN-IN
     Leave empty and the Google button shows setup instructions
     instead of failing silently.

     To turn it on:
       1. console.cloud.google.com -> APIs & Services -> Credentials
       2. Create an OAuth 2.0 Client ID, type "Web application"
       3. Authorised JavaScript origins: https://your-app.vercel.app
       4. Paste the Client ID below and redeploy.

     IMPORTANT: the Google credential is decoded in the browser so
     the demo can show you the account. A production build must
     send the raw JWT to a server and verify the signature there.
     ---------------------------------------------------------- */
  googleClientId: '',

  /* ----------------------------------------------------------
     ADMIN CONSOLE
     These live in browser JavaScript, which means anyone who
     opens DevTools can read them. This is fine for a demo or an
     internal preview. It is NOT security. Before you take real
     customers, move admin auth behind a server (see README).
     ---------------------------------------------------------- */
  admin: {
    username: 'admin',
    password: 'adminxadon123',
    recoveryEmail: 'officialxadonai@gmail.com'
  },

  /* Live telemetry poll interval, milliseconds */
  telemetryInterval: 8000,

  /* Password breach lookup (Have I Been Pwned k-anonymity range API).
     Only the first 5 characters of the SHA-1 hash ever leave the
     browser. Set to false to disable all outbound requests. */
  breachLookup: true,

  version: '5.0.0'
};
