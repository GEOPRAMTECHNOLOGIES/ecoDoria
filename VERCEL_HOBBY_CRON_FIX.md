# EcoDoria - Vercel Hobby Cron Fix

## What was fixed
- Changed the hourly `/api/cron/escalate` schedule (`0 * * * *`) to daily at 02:00 UTC.
- Kept the other maintenance tasks daily and the summary weekly; none runs more than once per day.
- Updated cron endpoints to accept GET requests, as used by native Vercel Cron.
- Updated authentication to accept Vercel's `Authorization: Bearer <CRON_SECRET>` header.
- Kept `X-Cron-Secret` support for external schedulers.
- Cron requests fail closed if `CRON_SECRET` is missing or incorrect.

## Required Vercel setting
In Vercel Project → Settings → Environment Variables, add:
- Name: `CRON_SECRET`
- Value: a long, random secret (do not share it or commit it)
- Environment: Production (and Preview only if you intend to run Preview cron jobs)

Redeploy after changing environment variables.

## Schedule (UTC)
- Escalation: daily at 02:00
- Hotspots refresh: daily at 02:15
- KYC retention: daily at 02:30
- Weekly summary: Mondays at 08:00

The Hobby plan cannot run the escalation task hourly. This fix makes it daily; it does not provide hourly monitoring.
