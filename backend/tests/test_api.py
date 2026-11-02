import base64
import uuid

import httpx
import pytest
import pytest_asyncio
from app import jobs
from app.core.config import get_settings
from app.db import create_all, dispose, sessionmaker
from app.main import app
from app.models import FeedEntry
from app.services import mailer, net_intel, sandbox_client
from app.services.net_intel import ExpandResult

KEY = {"X-Api-Key": "test-key"}
SCAM_TEXT = ("Dear HDFC customer, your account will be blocked today. Update KYC at "
             "https://hdfcbank-kyc-update.co/login and share the OTP to verify.")


@pytest_asyncio.fixture
async def client(monkeypatch, tmp_path):
    s = get_settings()
    monkeypatch.setattr(s, "report_dir", tmp_path / "reports")
    monkeypatch.setattr(s, "screenshot_dir", tmp_path / "screens")
    monkeypatch.setattr(s, "deep_scan_enabled", False)
    monkeypatch.setattr(s, "sandbox_enabled", False)
    monkeypatch.setattr(s, "report_mode", "demo")
    jobs.INLINE = True
    await dispose()
    await create_all()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c
    await dispose()


@pytest.fixture
def outbox(monkeypatch):
    sent = []

    async def fake_send(msg):
        sent.append(msg)
        return msg["Message-ID"]

    monkeypatch.setattr(mailer, "send", fake_send)
    return sent


async def register(client, **kw):
    body = {"app_version": "test", "state_code": "PB", "consent_version": 1,
            "consent_server_check": True, "consent_auto_report": True} | kw
    r = await client.post("/v1/devices/register", json=body, headers=KEY)
    assert r.status_code == 200
    return KEY | {"X-Device-Token": r.json()["device_token"]}


async def scan(client, h, sender, text=None, **kw):
    body = {"message_id": str(uuid.uuid4()), "sender": sender, "text": text,
            "received_at": "2026-11-01T14:30:00+05:30"} | kw
    return await client.post("/v1/scan", json=body, headers=h)


async def test_auth_required(client):
    assert (await client.post("/v1/devices/register", json={})).status_code == 401
    assert (await client.post("/v1/scan", json={}, headers=KEY)).status_code == 401


async def test_health(client):
    r = await client.get("/v1/health")
    assert r.json()["ok"] and r.json()["report_mode"] == "demo"


async def test_genuine_otp_safe(client):
    h = await register(client)
    r = await scan(client, h, "VM-HDFCBK-T", "482913 is your OTP for txn of Rs 500. Do not share it with anyone.")
    j = r.json()
    assert r.status_code == 200 and j["verdict"] == "SAFE" and j["report"] is None


async def test_no_server_consent_forbidden(client):
    h = await register(client, consent_server_check=False)
    assert (await scan(client, h, "9876543210", "hi")).status_code == 403


async def test_scam_auto_report_demo_flow(client, outbox):
    h = await register(client)
    r = await scan(client, h, "9876543210", SCAM_TEXT)
    j = r.json()
    assert j["verdict"] == "SCAM" and j["score"] >= 80 and j["status"] == "complete"
    assert j["impersonated_brand"] == "HDFC"
    assert {p["id"] for p in j["portals"]} >= {"ncrp", "chakshu"}
    rep = j["report"]
    assert rep["status"] == "awaiting_log" and rep["needs_log"] and rep["mode"] == "demo"
    assert any(x["kind"] == "state_cyber_cell" and not x["verified"] for x in rep["intended"])

    log = {"scan_id": j["scan_id"], "messages": [
        {"sender": "+91 98765 43210", "text": SCAM_TEXT, "received_at": "2026-11-01T14:30:00+05:30"},
        {"sender": "9876543210", "text": "Reminder: complete KYC now", "received_at": "2026-11-01T15:00:00+05:30"},
        {"sender": "9999999999", "text": "unrelated personal message — must NOT be included"},
    ]}
    r = await client.post("/v1/report/log", json=log, headers=h)
    assert r.json()["status"] == "demo_sent"

    assert len(outbox) == 1
    msg = outbox[0]
    assert msg["To"] == "team-demo@example.com"
    assert msg["Subject"].startswith("[DEMO] [ScamShield Auto-Report SS-")
    body = msg.get_body(("plain",)).get_content()
    assert "would be sent to" in body and "UNVERIFIED" in body and "unrelated personal" not in body
    names = {p.get_filename() for p in msg.iter_attachments()}
    assert any(n.endswith(".pdf") for n in names) and any(n.endswith(".json") for n in names)
    pdf = next(p for p in msg.iter_attachments() if p.get_filename().endswith(".pdf")).get_content()
    assert pdf[:4] == b"%PDF" and len(pdf) > 2000

    # same scam again from same sender + domain → de-duplicated
    j2 = (await scan(client, h, "9876543210", SCAM_TEXT)).json()
    assert j2["report"]["status"] == "duplicate"

    r = await client.get("/v1/reports", headers=h)
    assert [x["status"] for x in r.json()] == ["duplicate", "demo_sent"]


async def test_no_auto_report_without_consent(client, outbox):
    h = await register(client, consent_auto_report=False)
    j = (await scan(client, h, "9876543210", SCAM_TEXT)).json()
    assert j["verdict"] == "SCAM" and j["report"] is None


async def test_live_mode_skips_unverified(client, outbox, monkeypatch):
    monkeypatch.setattr(get_settings(), "report_mode", "live")
    h = await register(client)
    j = (await scan(client, h, "9876543210", SCAM_TEXT)).json()
    r = await client.post("/v1/report/log", json={"scan_id": j["scan_id"], "messages": []}, headers=h)
    assert r.json()["status"] == "no_recipient" and outbox == []


async def test_feed_hit_is_instant_scam(client):
    async with sessionmaker()() as s:
        s.add(FeedEntry(feed="openphish", indicator="totally-legit-parcel.top", type="domain"))
        await s.commit()
    h = await register(client)
    j = (await scan(client, h, "VM-ABCDEF", "Track your order at https://www.totally-legit-parcel.top/track")).json()
    assert j["verdict"] == "SCAM" and j["score"] == 100
    assert j["reasons"][0]["code"] == "FEED_HIT" and j["urls"][0]["feed_hits"] == ["openphish"]


async def test_private_mode_uses_device_codes(client):
    h = await register(client)
    r = await scan(client, h, "9876543210", None, urls=["https://hdfcbank-kyc-update.co/login"],
                   local={"score": 70, "reasons": ["KYC_BLOCK_THREAT", "OTP_REQUEST", "BRAND_CLAIM", "BOGUS"]})
    j = r.json()
    codes = {x["code"] for x in j["reasons"]}
    assert {"KYC_BLOCK_THREAT", "OTP_REQUEST", "MOBILE_BRAND_CLAIM", "LOOKALIKE_DOMAIN"} <= codes
    assert "BOGUS" not in codes and j["verdict"] == "SCAM"


async def test_admin_block_sender_and_blocklist(client):
    h = await register(client)
    await scan(client, h, "+91 70000 00001", "Congratulations you won KBC lottery, claim prize")
    auth = {"Authorization": "Basic " + base64.b64encode(b"admin:change-me").decode()}
    r = await client.put("/admin/senders/+917000000001", json={"status": "blocked"}, headers=auth)
    assert r.status_code == 200
    j = (await scan(client, h, "7000000001", "hello")).json()
    assert j["verdict"] == "SCAM" and j["reasons"][0]["code"] == "SENDER_BLOCKED"
    bl = (await client.get("/v1/sync/blocklist", headers=h)).json()
    assert "+917000000001" in bl["senders"] and bl["full"]
    assert (await client.get("/admin/stats", headers=auth)).status_code == 200
    assert (await client.get("/admin/stats")).status_code == 401


async def test_deep_scan_with_redirects_rdap_and_sandbox(client, outbox, monkeypatch):
    monkeypatch.setattr(get_settings(), "deep_scan_enabled", True)
    monkeypatch.setattr(get_settings(), "sandbox_enabled", True)

    async def fake_expand(url, *a, **k):
        return ExpandResult(input=url, final_url="https://bharat-demobank-kyc.example.net/login", hops=[
            {"url": url, "status": 301}, {"url": "https://t.example.org/r", "status": 302},
            {"url": "https://bharat-demobank-kyc.example.net/login", "status": 200}])

    async def fake_age(domain, *a, **k):
        return 2

    async def fake_visit(url, *a, **k):
        return {"final_url": url, "forms": [{"action_host": "x", "password": True}], "download_attempt": False,
                "screenshot": "abc.png"}

    monkeypatch.setattr(net_intel, "expand_url", fake_expand)
    monkeypatch.setattr(net_intel, "domain_age_days", fake_age)
    monkeypatch.setattr(sandbox_client, "visit", fake_visit)

    h = await register(client)
    r = await scan(client, h, "9123456780", "Bharat Demo Bank: your account is suspended. Verify at bit.ly/bdb-kyc")
    j = r.json()
    # In production this returns 202 + status "partial" and the app polls; INLINE jobs finish first.
    assert r.status_code in (200, 202)
    j = (await client.get(f"/v1/scan/{j['scan_id']}", headers=h)).json()
    codes = {x["code"] for x in j["reasons"]}
    assert j["status"] == "complete" and j["verdict"] == "SCAM" and j["score"] == 100
    assert {"REDIRECT_CHAIN", "LOOKALIKE_DOMAIN", "DOMAIN_NEW", "LOGIN_FORM", "MOBILE_BRAND_CLAIM"} <= codes
    assert j["impersonated_brand"] == "DEMOBANK"
    assert j["urls"][0]["final"] == "https://bharat-demobank-kyc.example.net/login"
    assert j["urls"][0]["screenshot_url"].endswith("/v1/screens/abc.png")
    assert j["report"]["status"] == "awaiting_log"
    assert any(x["kind"] == "brand" and x["verified"] for x in j["report"]["intended"])
