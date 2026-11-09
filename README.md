# EcoDoria — Environmental Patrol

Mobile-first environmental reporting for Kenya. Flask + MongoDB Atlas + Jinja, Leaflet/Turf, Tailwind CDN and Chart.js CDN.

## Important implementation boundary
This repository is a deployable foundation, not a legally or operationally certified public-money system. Before launch, complete the checklist below and conduct security, privacy, field and payment testing. The Daraja B2C credentials are intentionally unused: citizen rewards are wallet ledger credits and withdrawals are manually paid and reconciled by an administrator. Do not claim a transfer occurred until the M-Pesa transaction reference is recorded.

## Folder tree
```
ecodoria/
  app.py
  seed.py
  requirements.txt
  vercel.json
  .env.example
  .gitignore
  templates/
  static/
```

## Local setup
1. Python 3.11+ recommended: `python -m venv .venv && source .venv/bin/activate`.
2. `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env`; never commit `.env`.
4. Generate secrets:
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
   Put the Fernet output in `ENCRYPTION_KEY`, a random secret in `FLASK_SECRET_KEY` and `CRON_SECRET`.
5. Set Atlas `MONGODB_URI`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`; run `python seed.py`.
6. Start `flask --app app run` (set `FLASK_DEBUG=true` only locally).

## MongoDB Atlas
Create a free M0 cluster, database user and database `ecodoria`. In Network Access add `0.0.0.0/0` only if needed for Vercel's changing egress IPs; use least-privilege credentials and consider Atlas IP access controls/private networking where available. Put the SRV URI in `.env` locally and Vercel Environment Variables in production. `create_indexes()` creates unique, TTL and 2dsphere indexes at app startup. Collections include users, kyc, images, counties, layers, agencies, officers, routing_rules, reports, payouts, clawbacks, hotspots, settings, audit_log, otp_codes, officer_links.

## Integrations
- **Daraja production Buy Goods STK Push:** create a Safaricom Daraja app with Lipa na M-Pesa Online/STK Push enabled, complete Safaricom production go-live/onboarding, and use the production consumer key, consumer secret, production passkey and your active Buy Goods Till in `DARAJA_SHORTCODE`. Set `DARAJA_ENV=production`, `DARAJA_SHORTCODE_TYPE=buygoods`, and `DARAJA_CALLBACK_URL` to your public HTTPS callback base. The admin can initiate a customer-to-business STK prompt for a chosen phone and amount. The request uses `CustomerBuyGoodsOnline`; the customer must authorize with their M-Pesa PIN. The callback confirms payment asynchronously and records the M-Pesa receipt. An accepted STK request is not proof of payment. Buy Goods STK is for money collected into the Till; it is not B2C and does not pay citizen rewards. The app does not invoke B2C. Test a low-value payment and reconcile it in the merchant portal before production launch.
- **Africa's Talking:** configure username, API key and sender ID for OTP and officer SMS. Without credentials SMS is logged.
- **Resend:** configure API key and verified sender domain for email. Without credentials email is logged.
- **Vercel:** import repository, choose the Python runtime, and add the required `.env.example` variables in Project Settings → Environment Variables. Set a long random `CRON_SECRET` in Production (and Preview if needed). Native Vercel Cron sends `Authorization: Bearer <CRON_SECRET>` when that environment variable is configured; the cron endpoints accept this header and also retain `X-Cron-Secret` support for external schedulers. Cron endpoints accept GET as required by Vercel. The three daily maintenance jobs run at 02:00, 02:15 and 02:30 UTC; the weekly summary runs Mondays at 08:00 UTC. All schedules are compatible with Vercel Hobby's once-per-day frequency limit. If you need hourly escalation, use a Vercel plan that supports more frequent cron execution or an external scheduler.

## Wallet / receipts
Admin can credit any amount to a citizen wallet. A citizen updates the M-Pesa destination and requests withdrawal. Requests are reserved in the ledger for the next 15th or 1st. An administrator manually sends funds outside EcoDoria and records the transaction reference; only then can the citizen/admin view a receipt. This app does not initiate M-Pesa transfers.

## Data model (summary)
- `users`: phone, role, tier, level, reputation, wallet_balance, payout destination (Fernet ciphertext).
- `kyc`: user_id, encrypted ID number, encrypted image references, declaration, consent metadata, decision.
- `images`: bytes, content_type, owner_id, kind, encrypted, created_at, sha256.
- `counties`: name, active, GeoJSON geometry.
- `layers`: one feature per document, county, layer_type, geometry, version, active.
- `agencies`, `officers`, `routing_rules`: agency assignments, county scopes and routing matrix.
- `reports`: report_id, user_id, category, location, image id/hash, GPS evidence, status, geofence/fraud results.
- `payouts`: wallet credits, reward credits and manual withdrawal requests/settlements.
- `clawbacks`, `hotspots`, `settings`, `audit_log`, `otp_codes` (TTL), `officer_links` (48h expiry).

## Security and launch checklist
- Configure real admin authentication and officer provisioning; seed.py is bootstrap-only. Protect admin routes with strong credentials and MFA before public launch.
- Configure production CSRF, secure cookies, HTTPS, rate limits backed by Redis, secret rotation, backups and monitoring.
- Add full agency/officer management UI, GeoJSON upload/reprojection/version rollback, CSV/GeoJSON exports, charts, routing test console, county/branding editor, payout queue UI, clawback workflow and admin search/filters. Data collections and core primitives are established, but these operational screens are not all included in this starter.
- Implement transactional wallet accounting (MongoDB replica-set transactions), idempotency keys, reconciliation and maker-checker approval before real disbursements.
- Complete duplicate detection tests, robust GPS attestation, image size/metadata validation, county boundary validation, fraud model calibration and all cron authentication.
- Ensure report image privacy, avoid logging sensitive data, add retention/deletion workflows and data-subject request handling.
- Obtain Kenyan legal review for the refund clause and confirm ODPC registration and Data Protection Act 2019 compliance, DPIA, lawful basis, processor contracts and retention schedule before real launch.

## Legal note
The refund clause needs legal review and ODPC registration before real launch. Rewards and clawbacks must be governed by fair, transparent, appealable procedures and Kenyan law.


## Daraja Buy Goods STK Push configuration

Set these values in your deployment environment (do not commit real credentials):

- `DARAJA_ENV=sandbox` or `production`
- `DARAJA_CONSUMER_KEY` and `DARAJA_CONSUMER_SECRET`
- `DARAJA_BUSINESS_SHORTCODE`: the shortcode configured for the STK Push service; used in `BusinessShortCode` and to generate the STK password with `DARAJA_PASSKEY`.
- `DARAJA_PARTY_B`: the registered Buy Goods Till number sent as `PartyB`.
- `DARAJA_PASSKEY`: the Daraja STK passkey for the configured STK Push shortcode.
- `PUBLIC_BASE_URL`: the public HTTPS deployment URL. Safaricom must be able to reach the callback endpoint.

The admin payment dialog reports **successful** only after a successful Safaricom callback. A customer cancellation is shown separately from a failed request. If no final callback arrives, the dialog remains unconfirmed; it never treats a prompt being accepted as proof of payment.
