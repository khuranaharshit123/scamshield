# ScamShield: Next-Gen AI-Powered Anti-Scam SMS Ecosystem
### Complete Technical Architecture, Detection Pipeline & Presentation Guide

---

## 📌 Executive Summary

**ScamShield** is an advanced, privacy-first Android SMS platform designed to combat financial fraud, identity theft, and phishing delivered via SMS. By combining **instant on-device static heuristics**, **DeepSeek LLM contextual intelligence**, and an **enterprise-grade threat intelligence backend** with over **1.12 million live phishing indicators**, ScamShield detects, analyzes, and neutralizes SMS scams before users fall victim.

---

## 🚨 The Problem: Modern SMS Scams in India

Traditional SMS apps treat messages as simple text strings. Scammers exploit this gap using targeted tactics:

1. **Brand & Banking Impersonation:** Fake bank alerts (SBI, HDFC, PNB) claiming account suspension or KYC expiry.
2. **Fear & Coercion (Social Engineering):** Urgent utility disconnection threats ("Electricity power will be cut tonight at 9:30 PM"), fake court notices, or "Digital Arrest" threats.
3. **Malicious Link Redirection:** URL shorteners (`bit.ly`, `tinyurl`) masking credential phishing portals or auto-downloading trojan APKs (`.apk`, `.zip`).
4. **Alphanumeric Header Spoofing:** Simulating legitimate 6-character TRAI DLT commercial sender headers from personal 10-digit mobile numbers.
5. **Hinglish/Vernacular Manipulation:** Blending Hindi and English slang to bypass simple English keyword filters.

---

## 🛡️ Architecture: The 3-Tier Hybrid Defense System

ScamShield does not rely on a single checkpoint. It implements a multi-layered defense pipeline:

```
                           Incoming SMS
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
┌───────────────────────────────┐               ┌──────────────────────────────┐
│  Tier 1: On-Device Heuristics │               │  Tier 2: DeepSeek LLM AI     │
│  • Instant (<50ms), 100% offline               • Context & nuance awareness │
│  • TRAI DLT header validation │               • Hinglish & vernacular chat   │
│  • High-risk keyword matching │               • Psychological pressure check │
│  • Static URL & Punycode scan │               • Second-opinion verdict       │
│  • Local Room DB blocklist    │               │                              │
└───────────────┬───────────────┘               └──────────────┬───────────────┘
                │                                              │
                └───────────────────────┬──────────────────────┘
                                        ▼
                        Combined On-Device Verdict
                         (SAFE / SUSPICIOUS / SCAM)
                                        │
                         (If Server Sharing Enabled)
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  Tier 3: ScamShield Backend & Threat Intelligence Server                     │
│  • 1.12+ Million Phishing Indicators (OpenPhish + Phishing.Database)         │
│  • Recursive Redirect Expansion (Unmasking short links safely)               │
│  • RDAP Domain Age Query (Flags domains registered < 30 days ago)            │
│  • Cross-Device Sender Reputation Database                                   │
│  • Headless Sandbox (Playwright credential theft & APK download detection)   │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       ▼
                     Final Actionable Intelligence Card
              (Warning Breakdown + Manual Cyber Crime Reporting)
```

---

## 🔬 Detailed Tier Breakdown

### Tier 1: On-Device Heuristic Engine (Offline & Real-Time)
- **Execution Time:** < 50 milliseconds.
- **Privacy:** 100% on-device; operates without network access.
- **Header & Sender Classification:**
  - Evaluates whether the sender is a verified business entity (e.g., `VM-HDFCBK`, `AD-INDBNK-S`) following TRAI DLT norms, or an unverified personal 10-digit mobile number.
  - Flags personal numbers claiming to represent banks or public services.
- **Content Rule Scoring:**
  - Pattern matching for urgency triggers (KYC, electricity cutoff, lottery, OTP requests, job offers).
  - High-confidence scam triggers instantly add weighted risk points (0–100).
- **Static URL Analysis:**
  - Detects lookalike domains (e.g., `sbl-bank.xyz` imitating `sbi.co.in`).
  - Flags risky TLDs (`.top`, `.xyz`, `.club`), raw IP addresses, and direct `.apk` download links.
  - Evaluates domains against an offline encrypted Bloom filter / hash set synced to the local SQLite/Room database (`scamshield.db`).

### Tier 2: DeepSeek AI Contextual Scanner
- **Direct Engine Integration:** The Android client calls `api.deepseek.com` directly using the embedded API key.
- **Semantic Understanding:** Detects Hinglish nuances (e.g., *"Bhai turant account update kar le nahi to block ho jayega"*), conversational social engineering, and fake emergency loan lures that keyword lists miss.
- **Guardrails:**
  - The AI cannot downgrade a hard cryptographic blocklist hit (absolute evidence).
  - Verified official domains (e.g., `.gov.in`, official bank domains) prevent false-positive alarms.

### Tier 3: ScamShield Threat Intelligence Backend
- **Database Engine:** SQLite (local development) / PostgreSQL (production), storing **1,122,303** indicators.
- **Feed Ingestion Pipeline:**
  - **OpenPhish:** Live zero-day phishing targets.
  - **Phishing.Database:** Active repository of over 345,000 domains and 776,000 malicious links.
  - **URLhaus (abuse.ch):** Real-time malware distribution URLs.
- **Safe Link Sandboxing & Intelligence:**
  - **SSRF-Safe Redirect Expansion:** Recursively follows HTTP hops (up to 10 redirects) with strict loopback/private IP blocking to unmask shortened URLs (`bit.ly`, `is.gd`, `tinyurl`).
  - **RDAP Domain Age Verification:** Queries `rdap.org` in real time. Newly registered domains (< 30 days old) claiming to be established institutions are flagged immediately.
  - **Playwright Sandbox:** Headless browser visits suspicious links in an isolated container to inspect DOM structures for password/OTP input fields, credential-harvesting forms, or background file downloads, generating visual evidence screenshots.

---

## 🗄️ Database Architecture

### PC Backend Database (`backend/scamshield-dev.db` ~355 MB)
- `feed_entries`: 1,122,303 records indexing malicious indicators by type (`url`, `domain`, `ip`).
- `senders`: Global registry of observed senders with cross-device report counts and risk tiering.
- `scans`: Audit log of processed scans with encrypted text hashes, scores, and signal breakdowns.
- `urls`: Cache of expanded redirect hops, RDAP domain age, and sandbox verdicts.
- `devices`: Token-authenticated device registration records.

### Phone Database (`scamshield.db` Room SQLite on Android)
- `scan_results`: Local history of analyzed messages, verdicts, and reason breakdowns.
- `blocked_senders`: Synced list of admin-blocked senders for instant offline blocking.
- `blocked_domains`: Synced list of high-risk phishing domain hashes.
- `trusted_senders`: User-whitelisted contacts that bypass AI and backend checks.

---

## ⚖️ Performance Optimization: Zero-Lag In-Memory Caching

To guarantee smooth user experience on Android:
1. **Alphanumeric Fast-Path:** Commercial sender IDs (e.g., `AD-INDBNK-S`) are recognized by letter patterns and immediately bypass Android's `PhoneLookup` ContentProvider, eliminating hundreds of exceptions and IPC roundtrips.
2. **In-Memory Contact Cache:** Phone numbers are resolved once and cached in `ConcurrentHashMap`, turning 20ms disk queries into sub-millisecond memory reads.
3. **Reactive `StateFlow` Lifecycle:** Conversations are kept alive in an application-scoped `StateFlow`, rendering message lists instantly with zero loading spinners when navigating back from message threads.

---

## 🚨 Incident Reporting & Authority Integration

ScamShield empowers users to take immediate legal action **without sacrificing privacy or sending unauthorized emails**:

- **No Automatic Background Mail:** Background automatic dispatch is disabled (`reports_enabled: bool = False`), ensuring complete user consent.
- **Interactive Email Reporting Dialog:**
  - Users tap **"Email Report to Authority"** on any flagged message.
  - A dropdown selector allows targeting specific cyber cells:
    - **Punjab State Cyber Crime Cell** (`adgp.statecybercrime@punjabpolice.gov.in`)
    - **Delhi Police Cyber Crime (IFSO)** (`cybercell-delhi@nic.in`)
    - **National Cyber Crime Reporting** (`complaint-cybercrime@gov.in`)
    - **Haryana Cyber Crime** (`cybercell.haryana@hry.nic.in`)
    - **Custom / Other Authority Email** (for specific jurisdictional nodal officers)
  - Pre-fills a formal legal dossier in the user's native email client (Gmail/Outlook) containing:
    - Sender identity & message text
    - Risk score & verdict
    - Specific forensic flags (OTP demand, fake banking link, threat language)
    - Unmasked destination URLs and threat feed citations
  - The user reviews, edits, and taps **Send** manually.
- **National Portal Redirection:** Direct links to **National Cyber Crime Portal (`cybercrime.gov.in`)**, **Sanchar Saathi Chakshu (`sancharsaathi.gov.in`)**, and **Helpline 1930**.

---

## 📊 Presentation (PPT) Slide Deck Outline

Use this 12-slide structure to build your presentation:

### Slide 1: Title Slide
- **Title:** ScamShield — Autonomous AI & Threat Intelligence SMS Defense
- **Subtitle:** Next-Generation Protection Against Financial SMS Fraud & Phishing
- **Presenter:** [Your Name / Team Name]

### Slide 2: The Threat Landscape (Problem)
- SMS scams account for billions in fraudulent digital transfers in India.
- Tactics: KYC suspensions, electricity bill cutoff threats, fake parcel deliveries, digital arrests.
- Attackers exploit user urgency and short links on personal numbers.
- Traditional SMS apps are passive viewers that do zero active threat analysis.

### Slide 3: Introducing ScamShield
- What it is: A full replacement default SMS app for Android paired with an intelligent threat intelligence backend.
- Core philosophy: **Privacy-First + Multi-Layered Hybrid Defense**.
- Immediate on-device protection + Deep contextual AI + Live server threat intelligence.

### Slide 4: 3-Tier Defense Architecture
- **Tier 1:** On-Device Heuristic Engine (< 50ms, offline, sender analysis & regex).
- **Tier 2:** DeepSeek LLM (interprets Hinglish, urgency, and social engineering context).
- **Tier 3:** Backend Intelligence (1.12M threat feed database, RDAP domain age, link sandboxing).

### Slide 5: Tier 1 — On-Device Intelligence
- How TRAI DLT sender headers (`VM-HDFCBK`) differ from spoofed 10-digit mobile numbers.
- Offline regex scanning for KYC, OTP, and lottery scams.
- Local SQLite Room database caching known phishing domain hashes.
- Works 100% offline with zero data leaving the phone.

### Slide 6: Tier 2 — DeepSeek AI as Second Opinion
- Why rules alone fail: Attackers change spelling or mix Hindi/English.
- DeepSeek analyzes conversational nuances and coercion patterns.
- Guardrails ensure AI respects verified official domains and cannot overturn hard cryptographic blocklist hits.

### Slide 7: Tier 3 — Enterprise Threat Intelligence Backend
- **1,122,303 Live Indicators** stored in SQLite/PostgreSQL:
  - 345,014 phishing domains
  - 776,989 malicious links
  - OpenPhish live feed integration
- Recursive redirect expansion: follows short URLs (`bit.ly`) hop-by-hop safely.
- Real-time RDAP domain creation queries: flags websites registered < 30 days ago.

### Slide 8: Isolated Playwright Sandbox
- Inspects suspect pages without exposing the user's device.
- Automated detection of credential harvesting forms (PIN, OTP, credit card inputs).
- Detection of auto-downloaded malicious Android APK files.
- Visual screenshot capture for forensic reporting.

### Slide 9: User-Controlled Cyber Crime Reporting
- Respecting user privacy: Zero automated background emails.
- One-tap "Email Report to Authority" button.
- State-wise selection: Punjab Cyber Cell, Delhi Police IFSO, National Cyber Cell, or Custom.
- Auto-generates formal digital evidence dossier in the user's email client for manual review and submission.

### Slide 10: Performance Engineering & UX
- Instant rendering: In-memory `StateFlow` caching eliminates screen loading lag.
- Fast-path filtering: Skips contact lookups on commercial SMS headers.
- Persistent contact caching: Reduces UI thread load times from seconds to sub-milliseconds.

### Slide 11: Competitive Advantage & Differentiation
- Comparison Table:
  - Default SMS Apps (Google Messages / Truecaller) vs. **ScamShield**
  - Offline Rules + DeepSeek AI + Threat Feeds + Link Sandboxing + Authority Reporting.

### Slide 12: Conclusion & Future Roadmap
- Phase 1 Accomplished: Complete default SMS app, hybrid AI engine, live 1.12M feed sync, manual cyber crime reporting.
- Phase 2: React Admin Dashboard, automated DLT header verification, and automated national digest reporting.
- Open for Questions & Live Demonstration.

