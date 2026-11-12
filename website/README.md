# Public website (sentrigis.com)

Static marketing site served by the frontend image's nginx for the hostnames in
`SITE_HOSTNAMES` (on-prem: `cnapp-ctl site enable`; see docs/DEPLOY_ONPREM.md,
"Public website (optional)"). Baked into the frontend image at
`/usr/share/nginx/site` (frontend/Dockerfile).

- No inline scripts or styles and no third-party requests: the site's CSP is
  `'self'`-only. Styles live in `assets/site.css`, the form script in `assets/site.js`.
- Font: Plus Jakarta Sans, self-hosted (`assets/fonts/`, SIL Open Font License 1.1,
  `assets/fonts/OFL.txt`).
- "Log in" links point to `https://console.sentrigis.com`; nginx rewrites them to
  `SITE_CONSOLE_URL` (default `https://<CNAPP_HOSTNAME>`) when that differs.
- The "Request a demo" form posts to `POST /api/contact` (backend
  `app/api/contact.py`), which emails `CONTACT_TO`.
