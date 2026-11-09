# Collections and indexes

The canonical index creation is `create_indexes()` in `app.py`.

| Collection | Purpose | Key fields |
|---|---|---|
| users | citizens/admins | phone unique, role, tier, wallet_balance |
| kyc | verification cases | user_id, encrypted ID, image refs, status |
| images | all image bytes | bytes, content_type, owner_id, kind, sha256 |
| counties | county polygons | name unique, geometry, active |
| layers | one geospatial feature/document | county, layer_type, geometry, version |
| agencies | receiving agencies | name, active |
| officers | scoped officers | agency_id, counties, phone, email, role |
| routing_rules | category/county/layer mapping | category, county, layer_type, agency_id |
| reports | alleged environmental reports | report_id unique, user_id, location, status |
| payouts | wallet ledger and manual settlement | user_id, amount_kes, status, transaction_ref |
| clawbacks | recovery cases | user_id, report_id, amount, reason, status |
| hotspots | clustered areas | county, location, count |
| settings | thresholds and branding | key, value |
| audit_log | immutable action trail | actor_id, action, target, at |
| otp_codes | short-lived OTPs | phone, code_hash, expires_at TTL |
| officer_links | expiring report links | token_hash, officer_id, report_id, expires_at |

Geospatial indexes: `reports.location`, `layers.location` (feature documents should store a Point/geometry in `location` when imported), `hotspots.location`. The app currently stores layer geometry in `geometry`; add `layers.geometry` 2dsphere index for imported GeoJSON geometries.
\n- `stk_transactions`: inbound Daraja Buy Goods STK prompts, CheckoutRequestID, callback result, M-Pesa receipt and payment status. These are collections into the business Till, not user reward payouts.\n