# ◈ XADON Phone Defense

XADON Phone Defense is a premium SaaS-style security command center for device health, identity protection, threat analysis and guided lost-device response. The current package is a polished frontend foundation that can be deployed as a static demo while the production backend and device-provider integrations are connected.

## Product areas

The application includes a defender login workspace, an overview dashboard, realtime-style security event activity, security scoring, threat and URL analysis, account security checklists, device fleet health, incident response, guarded device controls, workspace settings and responsive mobile navigation.

The overview dashboard simulates incoming device heartbeats and signal refreshes so the product feels alive during demos. In production, those events should be replaced with authenticated server-sent events or WebSocket updates backed by a tenant-scoped event store.

## Device recovery boundary

A normal website cannot remotely locate, lock or factory-reset an arbitrary phone. XADON therefore exposes these controls as guarded workflows rather than pretending to have device access. Production execution must be connected to the appropriate official provider, such as Android Enterprise / Android Management API or Apple MDM / Find My integrations, with verified ownership, device enrollment, authorization checks, audit logging and explicit final confirmation.

The factory-reset control is intentionally non-executing in this package. It opens a confirmation safeguard and explains that an official device-management provider must be connected before a destructive action can be enabled. This is required to prevent unauthorized wipes and to preserve platform security boundaries.

## Routes

- `/login`
- `/main/phonedefense`
- `/main/threats`
- `/main/accounts`
- `/main/devices`
- `/main/emergency`
- `/main/settings`

## Production SaaS roadmap

For a real multi-tenant SaaS release, add a secure backend with organization and membership tables, device enrollment records, provider tokens stored server-side, event ingestion, audit logs, notification delivery, role-based access control, billing, rate limits and an incident state machine. The existing screens are structured so those procedures can replace the local demo state without redesigning the core product.

A production deployment should also add real authentication, encrypted secrets, CSRF/session protections, security headers, provider webhook verification, immutable recovery audit events, retention policies, support escalation and tests for every device action. Do not place provider credentials or destructive-action logic in browser JavaScript.

## Deploy

Upload the project to Vercel. `vercel.json` rewrites application routes to `index.html`. The package is intentionally dependency-free so the premium demo can be previewed immediately.

## v3 feature expansion

The latest build adds Security Analytics with score trends, signal mix, coverage health and downloadable security reports; Protection Policies with device, identity and recovery guardrails; and an immutable-style Audit Log for security events and response decisions. It also includes a command palette opened with `Ctrl/Cmd + K` for fast navigation between defense areas, policy controls, analytics and recovery.

These features are currently powered by a polished local demo state. Replace the local event array and browser storage with tenant-scoped database procedures, signed event ingestion, server-side policy evaluation and durable audit records when connecting the production backend.

## Billing and endpoint protection expansion

The current SaaS shell now includes a Billing & Plans page with active subscription status, usage meters, tier comparison, monthly/annual toggle, upgrade actions, invoices and payment-method management surfaces. Checkout and payment changes remain guarded until a real billing provider is connected; browser code never stores payment credentials.

The Antivirus Center adds layered endpoint-defense protocols for threat signatures, behavior monitoring, web protection and app integrity. It includes a realtime posture view, animated scan radar, deep-scan action, scheduled scan controls, download inspection, removable-media policy and a quarantine empty state. These are product surfaces ready to connect to a real endpoint agent or official device-management provider; the static demo does not claim to inspect arbitrary device files from a browser.

New application routes are `/main/billing` and `/main/antivirus`. All previous routes remain available.
