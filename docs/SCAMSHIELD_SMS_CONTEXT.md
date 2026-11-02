# ScamShield SMS — Project Context File (Android · Hackathon Build)

> **Purpose of this file:** the single source of truth for generating, building, and deploying the project.
> Feed it to any AI coding assistant or teammate before they write code. Every module, API, data model,
> deployment step and external data source is defined here. When code and this file disagree, update this file first.
>
> Working name: **ScamShield SMS** · package `com.scamshield.sms` (rename freely — search/replace both).

---

## 0. Locked decisions

| Area | Decision |
|---|---|
| Goal | Hackathon / competition build: working demo, sideloaded APK, no Play Store submission |
| Platform | **Android only** (minSdk 29, targetSdk = latest stable) |
| App type | **Full default SMS app** (replaces Google Messages): SMS + MMS + dual SIM |
| Android stack | **Kotlin + Jetpack Compose**, manual DI (`AppContainer`, no Hilt), Room (KSP), WorkManager, Retrofit/OkHttp, kotlinx.serialization, DataStore, Coil |
| Backend | **FastAPI (Python 3.12)** + PostgreSQL 16. Phase 1 runs background jobs as asyncio tasks in the API process (`app/jobs.py`); Celery + Redis only if load needs it |
| Link checking | **Server-side sandbox**: Playwright Chromium in an isolated Docker container |
| Sender reputation | Own PostgreSQL DB, seeded from public datasets/feeds and grown by app reports + rules on Indian sender-ID format |
| Reporting | **Automatic**: when a message is verified unsafe, the **server** emails the details + SMS log via the company mail system (SMTP) |
| Report recipients | National portals (cybercrime.gov.in / Chakshu: portal-ready packet), **state cyber cell email**, **impersonated bank**, **TRAI 1909** |
| Hosting | Existing **Hostinger VPS**, Docker Compose; the VPS's existing reverse proxy forwards `api.`/`admin.` to `127.0.0.1:8000`; deployed by GitHub Actions |

---

## 1. Product summary

ScamShield SMS is a complete Android SMS/MMS messaging app (threads, compose, send/receive, MMS images, dual-SIM, notifications, search, block) with a built-in security layer:

1. **Every incoming SMS is scanned** on arrival.
2. **Sender analysis**: the sender (10-digit number or DLT header such as `VM-HDFCBK-S`) is matched against the threat database and validated against Indian commercial-SMS header rules.
3. **Content analysis**: rules and a classifier detect scam patterns (KYC/PAN/Aadhaar block, OTP requests, lottery, parcel, electricity cut-off, job/loan fees, UPI collect/QR, "digital arrest").
4. **Link analysis**: every URL is expanded and **opened in a server sandbox** (never on the phone). The sandbox records the redirect chain, final domain, domain age, TLS details, page features (login forms, brand imitation, APK downloads) and checks threat feeds.
5. **Verdict**: `SAFE` / `SUSPICIOUS` / `SCAM`, with human-readable reasons. The verdict appears as a banner in the thread plus a high-priority alert. Links in SCAM messages are de-linked; the user must confirm to open them.
6. **Auto-report**: on a confirmed `SCAM` verdict the backend builds a report (JSON + PDF + message screenshot) and emails it to the configured authorities via the company SMTP. It applies de-duplication and rate limits, and runs in **demo mode** by default.

---

## 2. Scope

### In scope (hackathon)
- Default SMS role request and full default-app compliance (§4.2)
- Conversation list, thread view, compose, reply, multipart SMS, delivery reports, SIM picker
- MMS receive and send (images), with group MMS display only
- Notifications with direct reply and mark-as-read
- Search, block or unblock (system `BlockedNumberContract`), delete, archive
- Scan pipeline (on-device rules plus server verdict), verdict banners, scam alerts, safe link preview (sandbox screenshot)
- Auto-report pipeline with demo or live mode, and a report history screen
- Admin web dashboard (minimal): reports, sender DB, URL DB, toggle report mode
- Docker deploy on the VPS, plus CI for APK and backend

### Out of scope (post-hackathon)
- RCS: there is no third-party API; RCS stays in Google Messages
- iOS
- Play Store policy declarations
- Backup and restore to cloud, scheduled SMS
- On-device ML model (stretch goal, §6.5)

---

## 3. System architecture

```
┌──────────────────────── Android (Kotlin/Compose) ────────────────────────┐
│ SmsDeliverReceiver / MmsWapPushReceiver                                   │
│   → write to Telephony provider → enqueue ScanWorker (WorkManager)        │
│ ScanWorker:                                                               │
│   1. Local rules (sender format, keywords, URL heuristics, local blocklist)│
│   2. POST /v1/scan  (sender, urls, features; full text only per §10.2)    │
│   3. Save verdict to Room → update notification + thread banner           │
│ UI: Conversations · Thread · Compose · Scan details · Reports · Settings  │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │ HTTPS (Nginx, TLS, rate limit, API key + device token)
┌───────────────────────────────▼──────────────── VPS (Docker Compose) ─────┐
│ api (FastAPI) ── postgres ── redis                                        │
│   │  /v1/scan  /v1/report  /v1/sync/blocklist  /admin/*                  │
│   ▼                                                                       │
│ worker (Celery/RQ)                                                        │
│   • unshorten + RDAP/WHOIS + TLS + threat-feed lookups                    │
│   • calls sandbox → screenshot + page features                            │
│   • scoring → verdict → if SCAM ≥ threshold → report job                  │
│   • report job → PDF → SMTP (company mail) → authorities                  │
│ sandbox (Playwright Chromium, isolated net, no access to db/redis)        │
│ feed-sync (cron container: URLhaus, OpenPhish, Phishing.Database, etc.)   │
│ dashboard (React + Vite static, served by Nginx)                          │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Android app

### 4.1 Project setup
- Gradle Kotlin DSL with a version catalog (`gradle/libs.versions.toml`). Use the latest stable AGP, Kotlin and Compose BOM at generation time.
- `minSdk = 29` (needed for `RoleManager`), `targetSdk = compileSdk = latest stable`.
- Modules (single Gradle module is acceptable for the hackathon; use packages):
  ```
  com.scamshield.sms
  ├── core/telephony     # SMS/MMS send/receive, provider access, subscriptions
  ├── core/data          # Room DB, repositories, DataStore
  ├── core/network       # Retrofit API client, DTOs
  ├── core/security      # SenderAnalyzer, ContentRules, UrlExtractor, LocalBlocklist, Scorer
  ├── work               # ScanWorker, BlocklistSyncWorker, ReportStatusWorker
  ├── notify             # Channels, MessagingStyle notifications, direct reply
  ├── ui/conversations, ui/thread, ui/compose, ui/scan, ui/reports, ui/settings, ui/onboarding
  └── di                 # Hilt modules
  ```

### 4.2 Default SMS app requirements (Android will not offer the role without ALL of these)

```xml
<!-- AndroidManifest.xml (essentials) -->
<uses-permission android:name="android.permission.RECEIVE_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.RECEIVE_MMS"/>
<uses-permission android:name="android.permission.RECEIVE_WAP_PUSH"/>
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>   <!-- dual SIM subscription list -->
<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
<uses-permission android:name="android.permission.CHANGE_NETWORK_STATE"/> <!-- MMS data -->

<!-- 1. SMS deliver (only the default app receives SMS_DELIVER) -->
<receiver android:name=".core.telephony.SmsDeliverReceiver"
    android:permission="android.permission.BROADCAST_SMS" android:exported="true">
  <intent-filter><action android:name="android.provider.Telephony.SMS_DELIVER"/></intent-filter>
</receiver>

<!-- 2. MMS WAP push deliver -->
<receiver android:name=".core.telephony.MmsWapPushReceiver"
    android:permission="android.permission.BROADCAST_WAP_PUSH" android:exported="true">
  <intent-filter>
    <action android:name="android.provider.Telephony.WAP_PUSH_DELIVER"/>
    <data android:mimeType="application/vnd.wap.mms-message"/>
  </intent-filter>
</receiver>

<!-- 3. Compose activity for sms:/smsto:/mms:/mmsto: -->
<activity android:name=".ui.MainActivity" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.SEND"/>
    <action android:name="android.intent.action.SENDTO"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="sms"/><data android:scheme="smsto"/>
    <data android:scheme="mms"/><data android:scheme="mmsto"/>
  </intent-filter>
</activity>

<!-- 4. Quick "respond via message" from the dialer -->
<service android:name=".core.telephony.HeadlessSmsSendService"
    android:permission="android.permission.SEND_RESPOND_VIA_MESSAGE" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.RESPOND_VIA_MESSAGE"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <data android:scheme="sms"/><data android:scheme="smsto"/>
    <data android:scheme="mms"/><data android:scheme="mmsto"/>
  </intent-filter>
</service>
```

Role request (onboarding):
```kotlin
val rm = getSystemService(RoleManager::class.java)
if (rm.isRoleAvailable(RoleManager.ROLE_SMS) && !rm.isRoleHeld(RoleManager.ROLE_SMS)) {
    launcher.launch(rm.createRequestRoleIntent(RoleManager.ROLE_SMS))
}
```

Rules that apply once the app is the default:
- **The app itself must insert received SMS into `Telephony.Sms.Inbox`** (the system no longer does). Do this in `SmsDeliverReceiver` before scanning.
- Write sent messages to `Telephony.Sms.Sent` and update status from the sent/delivered `PendingIntent`s.
- Handle `Telephony.Sms.Intents.getMessagesFromIntent()` for multipart PDUs. Read `subscription` from extras for dual SIM.
- When the app loses the default role, degrade gracefully: show a "Set as default" banner and keep read-only scanning of existing messages.

### 4.3 Messaging features (functional parity checklist)
- [ ] Conversation list (from `Telephony.Threads` / `Sms.Conversations`), with contact names and photos, unread badges, a verdict chip per thread, pinned and archived threads
- [ ] Thread view: bubbles, timestamps, delivery ticks, SIM indicator, MMS images (Coil), copy, forward, delete
- [ ] Compose: recipient picker (contacts), SIM picker (`SubscriptionManager.getActiveSubscriptionInfoList`), character/part counter (`SmsManager.divideMessage`)
- [ ] Send: `context.getSystemService(SmsManager::class.java).createForSubscriptionId(subId).sendMultipartTextMessage(...)`
- [ ] MMS send and receive: `SmsManager.sendMultimediaMessage` / `downloadMultimediaMessage` with a `FileProvider` URI; PDU encode/decode using AOSP `com.google.android.mms.pdu` classes (Apache-2.0) vendored into `core/telephony/mms`. **Do not copy GPL code (e.g. QKSMS) unless the project is GPL.**
- [ ] Notifications: one channel per class (Messages, Scam alerts [high importance], Reports); `MessagingStyle`, direct reply (`RemoteInput`), mark read
- [ ] Search across messages
- [ ] Block or unblock number (`BlockedNumberContract`; available to the default SMS app), with a "Block & report" action
- [ ] Settings: report mode info, state selection (for cyber cell routing), consent management, server URL (debug), theme

### 4.4 Security layer — on-device

**Incoming flow (ScanWorker, expedited work):**
```
SMS_DELIVER → insert into provider → Room: scan_result(status=PENDING)
  → LocalScan (≤50 ms): SenderAnalyzer + ContentRules + UrlExtractor + LocalBlocklist → localScore, reasons
  → show the normal message notification immediately (do not block delivery)
  → if network: POST /v1/scan → serverScore, verdict, reasons, reportId?
  → Room update → if SCAM: replace notification with a "⚠ Scam detected" alert, banner in thread, links de-linked
  → if offline: verdict = local only, retry via WorkManager (backoff) when online
```

**SenderAnalyzer:** Indian sender formats.
- DLT header format: `XY-HEADER` or `XY-HEADER-S`, where `XY` is the operator/circle prefix, `HEADER` is up to 6 alphanumeric characters, and the suffix is `-P` (promotional), `-S` (service), `-T` (transactional) or `-G` (government). TRAI made the suffix mandatory from 6 May 2025.
  Regex: `^[A-Z]{2}-[A-Z0-9]{3,6}(-[PSTG])?$`
- Signals:
  - A 10-digit or `+91` mobile number whose text claims to be a bank, government body, courier or utility → high risk
  - A header whose content contains OTP/KYC/"account blocked" but the suffix is `-P` → risk
  - A header that imitates a known brand but does not match the curated `known_headers` list (e.g. `HDFCBK` vs `HDFCBNK`) → high risk
  - An international number (`+92`, `+234`, `+855`…), or a number with an unusual length → risk
  - A sender in the local blocklist (synced from server) → instant SCAM
  - A sender in the user's contacts → lower risk (but still scan links)

**ContentRules:** a weighted keyword/regex set in English, Hindi (Devanagari) and Hinglish:
KYC/PAN/Aadhaar update, "account will be blocked/suspended", OTP share request, lottery/KBC/prize, refund/cashback, electricity disconnection tonight, parcel held/customs, job or part-time "like videos", loan approved with a fee, "digital arrest"/police/CBI/customs threat, UPI collect/"scan QR to receive", APK link, urgency words, and a mismatch between the displayed brand and the link.

**UrlExtractor:** `Patterns.WEB_URL` plus a custom regex for scheme-less domains (`sbi-kyc.in/abc`), `wa.me`, `t.me` and UPI deep links (`upi://pay?pa=`). Normalize and de-duplicate.

**LocalBlocklist:** Room table synced daily from `/v1/sync/blocklist` (senders + URL host hashes). Use a Bloom filter in memory for fast lookups.

### 4.5 UI screens
1. Onboarding: explain the app → request the SMS role → notification permission → **consent screen for auto-reporting (§10.2)** → select state
2. Conversations: verdict chips (🟢 / 🟡 / 🔴)
3. Thread: red banner for SCAM ("Reported to Punjab Cyber Cell · Report #SS-2026-0042"), with a "Why?" sheet
4. Scan details: score, reasons, sender analysis, each URL with redirect chain, final domain, domain age, sandbox screenshot, feed hits
5. Reports: list of auto-reports with status (queued / sent / failed / demo) and recipients
6. Settings

### 4.6 Sideloading notes
- For the demo, distribute as a signed release APK (GitHub Release artifact).
- On recent Android versions, sideloaded apps can hit **"Restricted setting"** blocks for sensitive roles and permissions. If the SMS role or a permission is greyed out: App info → ⋮ → **Allow restricted settings**, then retry. Installing via `adb install` also works. Test this on the demo phone **before** the event.

### 4.7 Stretch: on-device ML
TF-IDF + logistic regression exported to TFLite, or a quantized MobileBERT/MuRIL text classifier through the MediaPipe Text Classifier task. Only attempt this after everything in §11 works.

---

## 5. Backend

### 5.1 Repository layout
```
scamshield/
├── android/                      # Android Studio project
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app, routers
│   │   ├── api/v1/scan.py, report.py, sync.py, admin.py, health.py
│   │   ├── core/config.py        # pydantic-settings, env vars (§9)
│   │   ├── core/security.py      # API key + device token, admin auth
│   │   ├── models/               # SQLAlchemy 2.0 models
│   │   ├── schemas/              # Pydantic DTOs
│   │   ├── services/
│   │   │   ├── sender_intel.py   # number/header reputation
│   │   │   ├── content_rules.py  # same rule set as Android (shared YAML)
│   │   │   ├── classifier.py     # TF-IDF + LR (joblib) text model
│   │   │   ├── url_intel.py      # unshorten, RDAP, TLS, feed lookups, lookalike
│   │   │   ├── sandbox_client.py # calls sandbox service
│   │   │   ├── scorer.py         # §5.4
│   │   │   ├── reporter.py       # report builder, routing, PDF, SMTP (§7)
│   │   │   └── feeds/            # urlhaus.py, openphish.py, phishing_db.py, webrisk.py, ...
│   │   └── workers/tasks.py      # Celery/RQ tasks
│   ├── alembic/                  # migrations
│   ├── data/
│   │   ├── rules.yaml            # content rules (shared with Android via build step)
│   │   ├── known_headers.yaml    # curated legit DLT headers per brand
│   │   ├── brand_domains.yaml    # official domains per brand (allowlist + lookalike targets)
│   │   └── authorities.yaml      # report routing (§7.4)
│   ├── ml/train.py, eval.py, model.joblib
│   ├── tests/
│   └── Dockerfile
├── sandbox/
│   ├── server.py                 # small FastAPI service wrapping Playwright
│   └── Dockerfile                # FROM mcr.microsoft.com/playwright/python
├── dashboard/                    # React + Vite admin
├── deploy/
│   ├── docker-compose.yml
│   ├── nginx/conf.d/scamshield.conf
│   └── .env.example
└── .github/workflows/backend.yml, android.yml, feeds.yml
```

### 5.2 Data model (PostgreSQL)

| Table | Key columns |
|---|---|
| `devices` | id, device_token_hash, app_version, state_code, consent_version, consent_at, created_at |
| `senders` | id, sender_raw, sender_norm, kind(`mobile`/`header`/`intl`/`short`), risk_score, first_seen, last_seen, report_count, status(`unknown`/`suspect`/`blocked`/`trusted`), source |
| `known_headers` | header, brand, category, verified(bool), source |
| `urls` | id, url_raw, url_final, host, registered_domain, first_seen, last_checked, verdict, score, feed_hits(jsonb), domain_age_days, tls(jsonb), sandbox(jsonb), screenshot_path |
| `scans` | id, device_id, sender_id, text_hash, text_enc(nullable, §10.2), features(jsonb), score, verdict, reasons(jsonb), created_at |
| `scan_urls` | scan_id, url_id, position |
| `reports` | id (`SS-YYYY-NNNN`), scan_id, mode(`demo`/`live`), recipients(jsonb), status, smtp_message_id, pdf_path, created_at, sent_at, error |
| `feed_entries` | id, feed, indicator, type(`url`/`domain`/`ip`/`number`), first_seen, last_seen |
| `audit_log` | id, actor, action, target, at |

Indexes: `senders(sender_norm)`, `urls(host)`, `urls(registered_domain)`, `feed_entries(indicator)`; GIN on JSONB as needed.

### 5.3 API (all JSON, `/v1`, header `X-Api-Key` + `X-Device-Token`)

`POST /v1/devices/register` → `{device_token}` (stores state and consent)

`POST /v1/scan`
```json
{
  "message_id": "local-uuid",
  "sender": "VM-HDFCBK-S",
  "received_at": "2026-11-01T14:30:00+05:30",
  "sim_slot": 1,
  "urls": ["http://bit.ly/x1y2"],
  "local": {"score": 55, "reasons": ["KYC_BLOCK_THREAT", "SHORTENER"]},
  "features": {"lang": "hi-en", "has_otp_request": false, "in_contacts": false},
  "text": "…"                      // only if consent.share_text == true (§10.2)
}
```
Response (sync if cached, otherwise `202` with `scan_id` and a poll at `GET /v1/scan/{id}`; target < 15 s end-to-end):
```json
{
  "scan_id": "…", "verdict": "SCAM", "score": 92,
  "reasons": [{"code": "LOOKALIKE_DOMAIN", "text": "Link imitates hdfcbank.com (hdfcbank-kyc-update.co)"},
              {"code": "DOMAIN_NEW", "text": "Domain registered 2 days ago"},
              {"code": "LOGIN_FORM", "text": "Page asks for net-banking password"}],
  "urls": [{"input": "http://bit.ly/x1y2", "final": "https://hdfcbank-kyc-update.co/login",
            "hops": 3, "screenshot_url": "/v1/screens/abc.png", "feed_hits": ["openphish"]}],
  "report": {"id": "SS-2026-0042", "status": "queued", "mode": "demo"}
}
```

Other endpoints:
- `POST /v1/report/log`: the device uploads the SMS log for an already-flagged sender, when the server requests it (see §7.2)
- `GET /v1/reports?device=…`: report statuses
- `GET /v1/sync/blocklist?since=…`: delta of blocked senders and URL host hashes
- `POST /v1/feedback`: user marks "not scam" or "scam" (feeds the retraining set)
- `GET /v1/health`
- Admin (JWT): `GET/PUT /admin/senders`, `/admin/urls`, `/admin/reports`, `PUT /admin/settings/report_mode`

### 5.4 Scoring (deterministic, explainable; tune on the test corpus)

| Signal | Points |
|---|---|
| URL or domain in any threat feed (URLhaus, OpenPhish, Web Risk…) | **→ 100 (instant SCAM)** |
| Sender in DB with status `blocked` | **→ 100** |
| Sandbox: password or OTP form on a non-official domain | +40 |
| Sandbox: APK or other executable download triggered | +40 |
| Lookalike or homoglyph of a brand in `brand_domains.yaml` (Levenshtein ≤ 2, brand token + extra words, punycode) | +30 |
| Mobile number sender claiming a bank, government body or utility | +30 |
| Domain age < 30 days | +25 |
| OTP or PIN share request | +20 |
| IP-literal URL / punycode / `@` in URL | +20 |
| Sender `report_count` ≥ 3 from distinct devices | +20 |
| Classifier P(scam) ≥ 0.8 | +20 (0.6–0.8: +10) |
| KYC/PAN/Aadhaar/account-block threat | +15 |
| Lottery/prize/refund/job-fee/loan-fee pattern | +15 |
| UPI collect or QR "to receive money" | +15 |
| Header impersonation (not in `known_headers`) | +15 |
| Redirect hops ≥ 3 or cross-domain redirect chain | +10 |
| Urgency words / no HTTPS / risky TLD | +5 each (max +15) |
| Prize/job/loan/refund offer from a personal mobile number (`MOBILE_COMMERCIAL`) | +15 |
| Sender in contacts | −15 |
| Final domain is an official brand domain and no other signals | −30 |

Verdict: `0–29 SAFE`, `30–59 SUSPICIOUS`, `≥ 60 SCAM`.
**Auto-report threshold: score ≥ 80, OR a feed hit, OR an admin-confirmed blocked sender.** Suspicious messages are never auto-reported.

---

## 6. Link sandbox ("trusted environment")

**Service:** `sandbox` container running `mcr.microsoft.com/playwright/python` with a tiny FastAPI app.
`POST /visit {url}` → returns the result below.

**Per visit:**
1. Unshorten first with `httpx` (HEAD, then GET, `follow_redirects=False`, loop ≤ 10 hops), recording every hop.
2. New Chromium **browser context per job** with an Android Chrome user-agent and mobile viewport (scam sites cloak based on device), `accept_downloads=False`, JavaScript enabled, 15 s navigation timeout, 25 s hard job timeout.
3. Route interception:
   - **Abort** requests to private, loopback or link-local IPs and Docker networks (SSRF guard; resolve the DNS and check the IP)
   - Record but do not save responses with APK, executable or zip content types (`DOWNLOAD_ATTEMPT` signal)
4. After `networkidle` or the timeout: full-page screenshot (PNG, max 1080×2400), page title, final URL, forms (action domain, `type=password`, OTP/card/Aadhaar field names), brand keywords and logos in text, iframe count, external script domains, `window.location` tricks, meta-refresh.
5. TLS: certificate issuer, not-before date (age), SAN match.
6. RDAP lookup for the registered domain (creation date, registrar); cache 7 days.
7. Tear down the context. Kill the browser after N jobs or after any crash.

**Isolation (mandatory, because the VPS also hosts other apps):**
- Separate Docker network `sandbox_net` that is **not** shared with Postgres or Redis. The worker reaches the sandbox over a dedicated `sandbox_ctl` network; the worker exposes no ports.
- Run as a non-root user, read-only root filesystem with a `tmpfs` for `/tmp`, `--cap-drop=ALL`, Chrome seccomp profile, `mem_limit: 1g`, `cpus: 1.0`, `pids_limit: 256`.
- Concurrency 2 visits at a time; queue the rest.
- Strongly recommended after the hackathon: move the sandbox to a **separate small VPS**. Visiting malicious sites from the main VPS IP can get that IP listed and can affect the other sites hosted there.

**Result JSON:**
```json
{"input":"…","hops":[{"url":"…","status":301}],"final_url":"…","title":"…",
 "screenshot":"abc.png","forms":[{"action_host":"…","password":true,"otp":false}],
 "download_attempt":false,"tls":{"issuer":"…","age_days":2},"rdap":{"created":"…","age_days":2},
 "brand_hits":["HDFC"],"errors":[]}
```

**Safe test targets:** Google's Safe Browsing test pages (`testsafebrowsing.appspot.com`), plus a team-hosted **fictional** brand ("Bharat Demo Bank") phishing-style page on a test subdomain. Never imitate a real bank in your own test pages.

---

## 7. Auto-reporting pipeline (company mail system)

### 7.1 Trigger
`scorer` returns SCAM with an auto-report condition (§5.4) **and** the device has consented (§10.2) → enqueue `build_and_send_report(scan_id)`.

### 7.2 What "SMS log" contains
- The flagged message (full text, sender, timestamp, SIM slot or operator if available)
- **All messages from the same scam sender** in that thread (the device uploads them on server request via `/v1/report/log`). **Never the rest of the inbox.**
- The URL analysis, redirect chain, sandbox screenshot, feed hits and reasons
- An auto-rendered image of the message bubble (Chakshu requires a screenshot for SMS reports)
- Reporter details are optional and sent only if the user entered them and consented (name, phone, state)

### 7.3 Report artefacts
- `report.json` (machine-readable)
- `report.pdf` (WeasyPrint or ReportLab): header with report ID and timestamp (IST); summary table (sender, scam type, verdict, score); message log; URLs with hops; screenshots; methodology note ("automated detection, not a legal determination"); app and contact info
- Email body: a plain-text summary plus HTML. Subject:
  `[ScamShield Auto-Report SS-2026-0042] Suspected <scam_type> SMS from <sender> — <state>`

### 7.4 Routing (`data/authorities.yaml`)

```yaml
# VERIFY every address before enabling live mode. Source of truth for state nodal officers:
# cybercrime.gov.in → Contact Us / State nodal officers list.
mode: demo                     # demo | live  (env REPORT_MODE overrides)
demo_recipients: ["reports-demo@yourdomain.in"]   # team inbox used at the hackathon
digest: {enabled: true, window_minutes: 60}       # batch per authority to avoid flooding

state_cyber_cells:
  PB:   # Punjab — candidates found on third-party directories, UNVERIFIED
    - adgp.statecybercrime@punjabpolice.gov.in
    - sp.scc@punjabpolice.gov.in
    - aigcc@punjabpolice.gov.in
  CH:   # Chandigarh UT — TODO from official nodal list
    - TODO
  # … other states from the official list

banks:      # impersonated brand → fraud/phishing reporting address (TODO: verify on each bank's official site)
  HDFC: TODO
  SBI:  TODO
  ICICI: TODO

national_portals:    # no email intake — the app generates a portal-ready packet and deep links
  ncrp_report_suspect: "https://cybercrime.gov.in"           # Report & Check Suspect → Report Suspect
  chakshu: "https://sancharsaathi.gov.in/sfc/"               # Suspected Fraud Communication
  helpline: "1930"

trai_1909:
  channel: sms                  # forward from the user's SIM; see 7.6
  auto_send: false              # needs explicit opt-in in settings
```

### 7.5 Sending
- SMTP of the company domain (Hostinger Mail, Zoho Mail, or AWS SES SMTP) via `aiosmtplib` / `fastapi-mail`, with STARTTLS on port 587.
- `From: ScamShield Reports <reports@yourdomain.in>`, `Reply-To: ops@yourdomain.in`. Set up SPF, DKIM and DMARC on the domain before the demo.
- **De-duplication:** one report per (authority, sender_norm, registered_domain) per 24 h. Later hits increment a counter and append to the next digest.
- **Rate limits:** ≤ 20 emails per authority per day in live mode, plus a global kill switch in the admin panel.
- Retries with exponential backoff (max 5). Store the SMTP `Message-ID`, and expose the status to the app.
- **Demo mode (default):** every email goes to `demo_recipients`. The real intended recipients are listed inside the body ("Would be sent to: …") so judges see the routing without emailing the police.

### 7.6 Channels that cannot be emailed
- **NCRP / Chakshu** take submissions only through their web forms, which need an OTP login. There is no public submission API, and the app must not automate those forms. The app shows a "Portal packet" screen: copy-ready fields, the generated screenshot, and buttons that open the portals.
- **TRAI 1909:** sending the forward uses the user's SIM, so it is opt-in in settings. When enabled, the app sends it with `SmsManager` after a scam verdict; otherwise it offers a one-tap forward.

---

## 8. Threat intelligence & databases

### 8.1 Government of India sources (reality check)
None of these offers a public bulk-download or lookup API for third-party apps. Use them as **manual verification links, routing targets and design references**, not as automated feeds. Do not scrape OTP- or captcha-protected portals.

| Source | Owner | What it is | Usable how |
|---|---|---|---|
| **NCRP "Report & Check Suspect" / Suspect Repository** (cybercrime.gov.in) | I4C, MHA | Citizen search of reported mobile numbers, emails, bank accounts, UPI IDs, websites and apps; also "Report Suspect" for numbers, URLs and SMS headers | Deep link "Check this sender on NCRP" in the scan sheet; report-routing target. No API. |
| **Central Suspect Registry** | I4C with banks and FIs | Registry of cybercriminal identifiers, shared with financial institutions | Not available to apps. Mention in the pitch as the ecosystem the app feeds. |
| **Chakshu — Sanchar Saathi** (sancharsaathi.gov.in/sfc) | DoT | Citizen reporting of suspected fraud calls, SMS and WhatsApp messages (screenshot mandatory for SMS) | Report target; the portal packet includes the auto screenshot. |
| **Digital Intelligence Platform (DIP)** | DoT | Secure data sharing between telecom operators, police, banks and others | Not accessible to citizens or apps. |
| **Financial Fraud Risk Indicator (FRI)** | DoT (DIU) | Medium / High / Very High risk rating per mobile number, for banks and UPI apps | Not public. Mirror the concept: the app's `senders.risk_score` uses the same 3 tiers in the UI. |
| **Mobile Number Revocation List (MNRL)** | DoT | Disconnected numbers, shared with banks and stakeholders | Not public. |
| **TRAI Header Information Portal** (smsheader.trai.gov.in) | TRAI | Lookup of the registered entity for a DLT header; email + OTP gated | Manual "verify header" link. Seed `known_headers.yaml` by hand for the top ~50 banks and brands (verify each on the portal). TRAI published older header lists as PDF/XLSX, which can be used as a starting seed if still downloadable. |
| **TRAI 1909** | TRAI | Unsolicited commercial communication complaints via SMS or call | Report channel (§7.6). |

### 8.2 URL / domain threat feeds (automated)

| Feed | Access | Notes |
|---|---|---|
| **URLhaus** (abuse.ch) | Free API with an **Auth-Key** (`urlhaus-api.abuse.ch/v1/`), plus bulk dumps | Malware distribution URLs. Same key works for ThreatFox. |
| **ThreatFox** (abuse.ch) | Same Auth-Key | IOCs (domains, IPs) |
| **OpenPhish Community feed** | Free text feed | Phishing URLs; pull hourly into `feed_entries` |
| **Phishing.Database** (GitHub `mitchellkrogza/Phishing.Database`) | Free, raw lists | Active phishing domains and links; sync daily |
| **phishunt.io** | Free API, no key, rate limited | Suspicious phishing domains from Certificate Transparency monitoring; filter by brand |
| **Google Safe Browsing v4 / Web Risk** | API key | Safe Browsing is for non-commercial use; **Web Risk** is the commercial product. Fine for the hackathon; switch before any commercial launch. |
| **VirusTotal** | Free public key | Very low quota and non-commercial terms. Use only for manual or admin lookups. |
| **AlienVault OTX** | Free key | Optional enrichment |
| **PhishTank** | Registration closed to new users since 2020 | Skip unless a teammate already has a key. |
| **RDAP** (`rdap.org` bootstrap) | Free | Domain creation date |
| **Tranco top-1M list** | Free | Allowlist of popular domains to reduce false positives |
| Curated `brand_domains.yaml` | Built by the team | Official domains of Indian banks, UPI apps, government (gov.in, nic.in), couriers, telecoms, utilities. Used for allowlisting and lookalike detection. |

`feed-sync` container: cron-driven pulls into `feed_entries`, normalized to registered domain + full URL; also publishes the device blocklist delta.

### 8.3 Datasets for the text classifier
| Dataset | Content | Use |
|---|---|---|
| UCI **SMS Spam Collection** | 5,574 English SMS, ham/spam | Baseline training |
| **Smishing Dataset I** (Timko & Rahman, 2024) | ~1,062 community-sourced smishing SMS with sender, brand and URL metadata | Smishing-specific positives |
| **Spam SMS in Hindi** (IEEE DataPort, NIT Silchar) | 3,894 Hindi SMS, spam/ham | Hindi coverage |
| **Hinglish & English scam dataset** (Hugging Face `bolewara/hinglish-scam-text-dataset`) | ~3.8k rows, but only a few dozen Hinglish rows | Hinglish seed only |
| Dravidian Spam SMS (IEEE DataPort) | ~7,700 SMS in Tamil, Telugu, Kannada, Malayalam, English | Optional |
| **Team-collected Indian scam SMS** | Screenshots and forwards from friends and family, anonymized | Most valuable; target 300+ |

Model: TF-IDF (word + char n-grams) + logistic regression → `model.joblib`. Report precision and recall on a held-out Indian-only set. Keep the classifier at ≤ 20 points in the score so rules and links dominate (explainability).

---

## 9. Configuration (`deploy/.env.example`)

```
APP_ENV=production
API_KEY=change-me
JWT_SECRET=change-me
DATABASE_URL=postgresql+psycopg://scam:scam@postgres:5432/scamshield
REDIS_URL=redis://redis:6379/0
SANDBOX_URL=http://sandbox:8100
REPORT_MODE=demo                 # demo | live
DEMO_RECIPIENTS=reports-demo@yourdomain.in
SMTP_HOST=smtp.hostinger.com
SMTP_PORT=587
SMTP_USER=reports@yourdomain.in
SMTP_PASSWORD=change-me
MAIL_FROM="ScamShield Reports <reports@yourdomain.in>"
ABUSECH_AUTH_KEY=
GOOGLE_SAFEBROWSING_KEY=
VIRUSTOTAL_KEY=
SCREENSHOT_DIR=/data/screens
REPORT_DIR=/data/reports
```
Android `local.properties` / BuildConfig: `API_BASE_URL`, `API_KEY` (demo only; real builds use per-device tokens).

---

## 10. Privacy, consent & legal

### 10.1 Principles
- The app works as a normal SMS app without the server. Scanning degrades to on-device rules when offline.
- Data minimization: by default the server receives the sender, the URLs and derived features, not the message text.

### 10.2 Consent (onboarding, versioned; stored as `consent_version` and `consent_at`)
1. "Check links and senders with ScamShield servers" (required for server verdicts)
2. "When a message is confirmed as a scam, **automatically send** it, all messages from that sender, the analysis and (optionally) your contact details to cyber-crime authorities and the impersonated organisation" (**required for auto-report**; if declined, the app shows the portal packet instead)
3. "Auto-forward scam SMS to TRAI 1909 from my SIM" (optional, off by default)

Write the consent text plainly in English and Hindi. Follow the DPDP Act 2023 principles: purpose limitation, a way to withdraw consent in Settings, and deletion on request.

### 10.3 Retention
- Message text and logs: kept 90 days after the report is sent, then deleted
- Screenshots: 90 days
- Hashes and indicators: kept indefinitely
- Encrypt `text_enc` at rest (Fernet key from env)

### 10.4 Disclaimers
In-app and in every report: automated detection can be wrong; the report is not a legal determination. Provide a "Not a scam" feedback button.

---

## 11. Hackathon must-have demo flow
1. Install the APK → onboarding → set as default SMS app → consent → state = Punjab
2. Send a normal SMS from a teammate → arrives, 🟢 SAFE
3. Send a fake "Bharat Demo Bank KYC" SMS with a shortened link to the fictional phishing page, from a 10-digit number → within ~10 s: 🔴 alert, reasons, redirect chain, sandbox screenshot
4. Open the Reports screen → "SS-2026-0001 · sent (demo)" → show the received email + PDF in the team inbox, with the "Would be sent to: Punjab State Cyber Cell, Bharat Demo Bank" routing
5. Show the portal packet with NCRP and Chakshu buttons
6. Admin dashboard: the new sender appears with its risk tier; block → the blocklist syncs to the phone
7. Bonus: emulator fallback via `adb emu sms send 9876543210 "…"`

---

## 12. Deployment (Hostinger VPS)

### 12.1 Server prep (one-time)
- Ubuntu LTS, non-root deploy user, SSH key-only login, UFW: allow 80, 443 and SSH. fail2ban.
- Install Docker Engine + the Compose plugin.
- DNS: `api.yourdomain.in` and `admin.yourdomain.in` → VPS IP.
- Nginx (container) + certbot (container or host) for Let's Encrypt.
- **Deploy from GitHub Actions**, not from the campus network (college Wi-Fi blocks port 22). For manual access off campus, use a Tailscale or Cloudflare Tunnel, or an SSH port the network allows.

### 12.2 `deploy/docker-compose.yml` (skeleton)
```yaml
services:
  nginx:
    image: nginx:stable
    ports: ["80:80", "443:443"]
    volumes: ["./nginx/conf.d:/etc/nginx/conf.d:ro", "certs:/etc/letsencrypt", "./dashboard-dist:/usr/share/nginx/admin:ro"]
    depends_on: [api]
    networks: [edge]
  api:
    image: ghcr.io/<owner>/scamshield-api:${TAG:-latest}
    env_file: .env
    volumes: ["data:/data"]
    depends_on: [postgres, redis]
    networks: [edge, backend]
  worker:
    image: ghcr.io/<owner>/scamshield-api:${TAG:-latest}
    command: celery -A app.workers.tasks worker -c 4 --loglevel=info
    env_file: .env
    volumes: ["data:/data"]
    networks: [backend, sandbox_ctl, egress]
  feed-sync:
    image: ghcr.io/<owner>/scamshield-api:${TAG:-latest}
    command: celery -A app.workers.tasks beat --loglevel=info
    env_file: .env
    networks: [backend, egress]
  sandbox:
    image: ghcr.io/<owner>/scamshield-sandbox:${TAG:-latest}
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: [ALL]
    security_opt: ["seccomp=./seccomp/chrome.json", "no-new-privileges:true"]
    mem_limit: 1g
    cpus: 1.0
    pids_limit: 256
    volumes: ["screens:/screens"]
    networks: [sandbox_ctl, sandbox_net]
  postgres:
    image: postgres:16
    environment: {POSTGRES_USER: scam, POSTGRES_PASSWORD: scam, POSTGRES_DB: scamshield}
    volumes: ["pg:/var/lib/postgresql/data"]
    networks: [backend]
  redis:
    image: redis:7
    networks: [backend]
networks:
  edge: {}
  backend: {internal: true}
  sandbox_ctl: {internal: true}
  sandbox_net: {}        # internet egress for the sandbox only
  egress: {}
volumes: {pg: {}, data: {}, screens: {}, certs: {}}
```
Share screenshots between the sandbox and the API by mounting the `screens` volume read-only into `api`.

### 12.3 Nginx
- `api.yourdomain.in` → `api:8000`, `client_max_body_size 5m`, `limit_req` 10 r/s per IP (burst 20), HSTS
- `admin.yourdomain.in` → static dashboard + `/admin` proxy, optional basic auth or an IP allowlist

### 12.4 Backups
Nightly `pg_dump` (cron container) → compressed → off-box storage (S3-compatible or Google Drive via rclone). Keep 7 daily copies.

---

## 13. CI/CD (GitHub Actions)

**backend.yml** (on push to `main` touching `backend/**`, `sandbox/**` or `deploy/**`):
1. `ruff` + `pytest` (rules, scorer, URL normalizer, report routing with SMTP mocked)
2. Build and push `scamshield-api` and `scamshield-sandbox` to GHCR (tag = git SHA)
3. SSH to the VPS (`appleboy/ssh-action`, secrets `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`):
   `cd /opt/scamshield/deploy && TAG=$SHA docker compose pull && docker compose up -d && docker compose exec -T api alembic upgrade head`
4. Smoke test: `curl -fsS https://api.yourdomain.in/v1/health`

**android.yml** (on push to `main` touching `android/**`, and on tags `v*`):
1. JDK 17, Gradle cache, `./gradlew lint testDebugUnitTest`
2. Decode the keystore from the `ANDROID_KEYSTORE_B64` secret → `assembleRelease`
3. Upload the APK artifact; on a tag, attach it to a GitHub Release (optional: Firebase App Distribution)

**feeds.yml:** nightly workflow that retrains the classifier only when the labelled data changed and commits `model.joblib` (optional).

---

## 14. Testing
- **Unit (Kotlin):** SenderAnalyzer (header regex incl. suffixes, mobile vs header), ContentRules (EN/HI/Hinglish), UrlExtractor edge cases (scheme-less, trailing punctuation, upi://)
- **Instrumented:** role-held flows on an emulator, `SMS_DELIVER` handling, provider writes, notification posting
- **Emulator SMS injection:** `adb emu sms send <number> "<text>"`
- **Backend:** pytest with fixtures for feed hits, a lookalike corpus, and sandbox results (recorded JSON)
- **Corpus:** `backend/tests/corpus/*.jsonl` with 100 labelled Indian SMS (50 scam, 50 genuine bank/OTP/delivery). CI fails if precision < 0.9 or recall < 0.8 on the corpus.
- **Manual:** dual-SIM send, long multipart SMS, MMS image round-trip, losing and regaining the default role, offline arrival → later server verdict

---

## 15. Build plan (adjust to the hackathon deadline)

| Day | Android | Backend / infra |
|---|---|---|
| 1 | Project scaffold, manifest, role request, receivers writing to the provider | Repo, compose stack on VPS, FastAPI skeleton, DB + Alembic, CI |
| 2 | Conversation list, thread view, send SMS, dual SIM | Rules + scorer, `/v1/scan`, feed-sync (URLhaus, OpenPhish, Phishing.Database) |
| 3 | Notifications + direct reply, compose, contacts, block | Sandbox service + isolation, RDAP/TLS, lookalike detection |
| 4 | ScanWorker, verdict banners, scan details sheet, offline rules | Report builder, PDF, SMTP (demo mode), routing YAML, digest |
| 5 | MMS send and receive, Reports screen, portal packet | Admin dashboard, blocklist sync, classifier v1 |
| 6 | Polish, onboarding consent, Hindi strings | Load test (`locust` 20 rps), backups, HTTPS hardening |
| 7 | Demo rehearsal on the real phone (restricted-settings check) | Final data seeding, verify recipients, freeze |

48-hour compressed version: days 1–4 only, with MMS reduced to receive-only display and the dashboard reduced to a read-only reports table.

---

## 16. Coding conventions for generation
- Kotlin: coroutines + Flow, unidirectional state (`ViewModel` + `UiState`), no business logic in Composables, all telephony behind interfaces (fakeable in tests).
- Python: typed (mypy-friendly), Pydantic v2, SQLAlchemy 2.0 style, async FastAPI handlers; long work only in workers.
- Rule sets live in `data/*.yaml` and are shared by Android (copied to `assets/` at build time) and the backend. Never duplicate keyword lists in code.
- Every verdict carries `reasons[{code, text}]`. Codes are stable enums used by the UI and the PDF.
- Never log message text; log `text_hash` and IDs only.
- No real bank branding in demo assets.

---

## 17. Implementation status (phase 1, 1 Nov 2026)

| Part | Status |
|---|---|
| Shared rules (`shared/rules.yaml`, `shared/brands.yaml`) + export to Android assets | Done. Content categories support `negations` (e.g. "do not share your OTP" no longer triggers OTP_REQUEST) |
| Backend: sender/content/URL analysis, scorer, API, device auth, blocklist sync, admin API | Done, 73 tests incl. corpus gate (precision 1.00, recall 0.96 on 48 labelled SMS) |
| Deep URL analysis: SSRF-safe redirect expansion, RDAP age, feed lookup | Done (unit-tested with mocked network) |
| Link sandbox (Playwright) | Done; live-tested against a local fake phishing page (password+OTP form, APK download, brand hit detected; SSRF guard blocks localhost) |
| Threat feeds: OpenPhish, Phishing.Database, URLhaus parsers + upsert + scheduler | Done (parsers tested; live download untested offline) |
| Auto-report: consent, routing, demo/live, dedupe, daily cap, PDF + JSON + email, SMS-log upload | Done (`tools/demo_report.py` produces a sample) |
| Android: default-SMS manifest + receivers, provider read/write, send (multipart, dual SIM, status), notifications with reply, on-device scanner, ScanWorker, blocklist sync, Compose UI (onboarding, conversations, thread, details sheet, reports, settings) | Written. Security core compiled on the JVM and **identical to the Python scorer on 58/58 messages** (`tools/parity`). The Android layer is syntax-checked only — first build in Android Studio may need small fixes |
| MMS download/send, admin web dashboard, message-bubble screenshot for Chakshu, text classifier, report digest | Phase 2/3 |

## 18. Open items (fill in before generating code)
- [ ] Final app name and package
- [ ] Hackathon name and deadline (sets the §15 plan)
- [ ] Company domain and mailbox for SMTP (`reports@…`), with SPF/DKIM/DMARC status
- [ ] Verified state cyber cell addresses (official nodal list) and bank fraud addresses
- [ ] Demo phone model and Android version (dual SIM? restricted-settings behaviour)
- [ ] Team split (Android vs backend vs data)
- [ ] Whether to buy a second tiny VPS for the sandbox
