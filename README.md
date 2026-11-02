# ScamShield SMS

Android default-SMS app that checks every incoming message for scams (sender, wording, links),
opens links only in a server sandbox, and — with the user's consent — automatically emails a
report to cyber-crime authorities through the company mail server.

The full design is in [`docs/SCAMSHIELD_SMS_CONTEXT.md`](docs/SCAMSHIELD_SMS_CONTEXT.md) (§17 = what's built).

```
shared/        rules.yaml + brands.yaml — the ONLY place scam keywords, brands, headers, points live
backend/       FastAPI API, scoring, deep URL analysis, auto-reports, threat feeds (Python 3.12)
sandbox/       Isolated Playwright browser service that opens links (Docker)
android/       Kotlin + Jetpack Compose default SMS app
deploy/        docker-compose.yml, .env.example, Nginx snippet for the VPS's existing proxy
tools/         export_rules.py · parity/ (Kotlin ↔ Python check) · demo_report.py
.github/       CI: tests, image build, deploy to VPS, APK build
```

## Run the backend locally

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements-dev.txt
cd backend
pytest -q                                    # 73 tests, incl. the corpus quality gate
uvicorn app.main:app --reload                # http://localhost:8000/docs  (SQLite, demo mode)
```

Without `SMTP_HOST`, report emails are written to `var/reports/outbox/*.eml` instead of being sent.

Sample report without any setup: `python tools/demo_report.py demo-out` → `demo-out/SS-2026-0001/*.pdf`.

## Sandbox locally

```bash
pip install -r sandbox/requirements.txt && playwright install chromium   # or CHROMIUM_PATH=/usr/bin/google-chrome
cd sandbox && uvicorn server:app --port 8100
# backend: SANDBOX_ENABLED=true SANDBOX_URL=http://localhost:8100
```

## Android

1. Open `android/` in Android Studio (Ladybug or newer). If prompted, accept the AGP upgrade.
2. `android/local.properties`:
   ```
   scamshield.apiBaseUrl=https://api.yourdomain.in/     # emulator + local backend: http://10.0.2.2:8000/
   scamshield.apiKey=<API_KEY from deploy/.env>
   ```
3. Run on a phone with a SIM → onboarding → **Set as default SMS app**. Sideloaded APK and the option
   is greyed out? App info → ⋮ → *Allow restricted settings*.
4. Emulator test SMS: `adb emu sms send 9123456780 "Bharat Demo Bank: account suspended, verify at bit.ly/bdb-kyc"`

After editing anything in `shared/`, run `python tools/export_rules.py` (CI fails if you forget).
`tools/parity/run_parity.sh` proves the phone and the server score messages identically.

## Deploy (Hostinger VPS)

1. VPS: Docker + Compose plugin, `mkdir -p /opt/scamshield/deploy`, copy `deploy/.env.example` → `/opt/scamshield/deploy/.env` and fill it in (`chmod 600`).
2. Add `deploy/nginx/scamshield.conf` to the proxy that already serves ports 80/443; DNS `api.` and `admin.` → VPS (Cloudflare).
3. GitHub secrets: `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY` (`VPS_SSH_PORT` if not 22), `SCAMSHIELD_API_KEY`, keystore secrets; variable `SCAMSHIELD_API_BASE_URL`.
4. Push to `main` → tests → images to GHCR → `docker compose up -d` on the VPS → health check.
   (Deploys run from GitHub, so campus Wi-Fi blocking port 22 doesn't matter.)
5. Make the GHCR packages public, or run `docker login ghcr.io` once on the VPS.

## Before switching `REPORT_MODE=live`

Every address in `backend/data/authorities.yaml` is unverified until checked against the official
nodal-officer list on cybercrime.gov.in; unverified addresses are never emailed in live mode.
Same for `verified: false` SMS headers in `shared/brands.yaml` (check on smsheader.trai.gov.in).

## Admin (demo)

```bash
curl -u admin:$ADMIN_PASSWORD https://admin.yourdomain.in/admin/stats
curl -u admin:$ADMIN_PASSWORD -X PUT https://admin.yourdomain.in/admin/senders/+919123456780 \
     -H 'content-type: application/json' -d '{"status":"blocked"}'
```
