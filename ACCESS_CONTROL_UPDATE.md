# EcoDoria Access-Control Update

- Admin login route is configurable through `ADMIN_ROUTE`; the static `/admin/login` endpoint is disabled.
- All `/admin...` URLs are guarded centrally and still have route-level `@require("admin")` checks.
- Public navigation and citizen login no longer display Admin or Officer links.
- Officers authenticate with username/password at `/officer/<username>`.
- Officer sessions bind to MongoDB officer `_id`; authorization and report scope are derived from the session, not the URL.
- Admin dashboard supports create, edit, activate/deactivate and password reset, plus agency and county assignment.
- Existing MongoDB officer/report/user records are not deleted or rewritten by this update. Legacy officers need their username/password and active status configured in the dashboard before login.
- Daraja settings, encryption key settings, SMTP settings, MongoDB settings and cron configuration are preserved.
