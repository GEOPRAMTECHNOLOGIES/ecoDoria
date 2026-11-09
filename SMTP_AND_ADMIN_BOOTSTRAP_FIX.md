# EcoDoria SMTP and Bootstrap Administrator Update

## Email provider
Resend integration and `RESEND_API_KEY` have been removed. Email is sent using these five SMTP settings:
1. `SMTP_HOST`
2. `SMTP_PORT`
3. `SMTP_USERNAME`
4. `SMTP_PASSWORD`
5. `SMTP_FROM`

For Gmail: use `smtp.gmail.com`, port `587`, your Gmail address as username, a Google App Password as password, and a verified sender address in `SMTP_FROM`. Do not use your normal Gmail password.

## Administrator bootstrap / previous Forbidden error
The admin login no longer returns `Forbidden - Run seed.py to create the bootstrap administrator` when the configured admin account is absent. After the submitted email and password match `ADMIN_EMAIL` and `ADMIN_PASSWORD_HASH`, the application creates the initial admin record in MongoDB and signs the administrator in. MongoDB must allow inserts into the configured database.

You do not need to run `seed.py` on Vercel. The script remains available for optional manual/local seeding. Set `ADMIN_PASSWORD_HASH` in Vercel. Generate it securely using:
`python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YOUR-STRONG-PASSWORD'))"`

Keep `ADMIN_PASSWORD_HASH` and all SMTP values private. Never commit real credentials to GitHub. Redeploy after changing Vercel environment variables.
