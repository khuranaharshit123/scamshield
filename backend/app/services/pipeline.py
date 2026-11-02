"""Scan pipeline: quick (in-request) analysis, then deep URL analysis in the background.

quick_scan  : sender + content + static URL rules + DB lookups (feeds, sender reputation,
              cached deep results)  → verdict in < 1 s
deep_scan   : redirect expansion, RDAP domain age, sandbox visit → rescore → maybe auto-report
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.crypto import encrypt_json
from app.feeds.lookup import feed_hits
from app.models import Device, Scan, Sender, SenderDevice, Url, utcnow
from app.schemas import ScanIn
from app.services import net_intel, sandbox_client
from app.services.content_rules import brands_mentioned, claims_brand, content_signals, signals_from_device_codes
from app.services.ruleset import RuleSet, get_ruleset
from app.services.scorer import ScoreResult, score
from app.services.sender_intel import classify_sender, sender_signals
from app.services.signals import Signal
from app.services.url_intel import extract_urls, parse_url, static_url_signals

log = logging.getLogger(__name__)


def _sig(d: dict) -> Signal:
    return Signal(**d)


def as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# ---------------------------------------------------------------- sender DB
async def upsert_sender(session: AsyncSession, raw: str) -> Sender:
    info = classify_sender(raw)
    sender = (await session.execute(select(Sender).where(Sender.sender_norm == info.norm))).scalar_one_or_none()
    if sender is None:
        sender = Sender(sender_norm=info.norm, sender_raw=raw[:64], kind=info.kind)
        session.add(sender)
        await session.flush()
    sender.last_seen = utcnow()
    return sender


def db_sender_signals(sender: Sender, rs: RuleSet) -> list[Signal]:
    if sender.status == "blocked":
        return [Signal("SENDER_BLOCKED", 100, "This sender is on the ScamShield blocklist", "db",
                       absolute=True, detail=sender.sender_norm)]
    if sender.report_count >= 3:
        return [Signal("SENDER_REPORTED", rs.pts("SENDER_REPORTED"),
                       f"{sender.report_count} other ScamShield users received scam messages from this sender",
                       "db", detail=sender.sender_norm)]
    return []


async def mark_sender_scam(session: AsyncSession, sender: Sender, device: Device, score_value: int) -> None:
    exists = await session.get(SenderDevice, (sender.id, device.id))
    if exists is None:
        session.add(SenderDevice(sender_id=sender.id, device_id=device.id))
        await session.flush()
        sender.report_count = (await session.execute(
            select(func.count()).select_from(SenderDevice).where(SenderDevice.sender_id == sender.id)
        )).scalar_one()
    sender.risk_score = max(sender.risk_score, score_value)
    if sender.status == "unknown":
        sender.status = "suspect"
    sender.updated_at = utcnow()


# ---------------------------------------------------------------- URLs
async def quick_url(session: AsyncSession, raw: str, rs: RuleSet) -> dict | None:
    st = static_url_signals(raw, rs)
    if st is None:
        return None
    p = st.parsed
    entry = {
        "input": raw, "final": p.url if not p.is_upi else raw, "host": p.host or None,
        "registered_domain": p.registered_domain or None, "hops": 0, "screenshot": None,
        "feed_hits": [], "official": st.official, "imitates": st.imitates,
        "signals": [s.as_dict() for s in st.signals], "deep": False,
    }
    if p.is_upi:
        entry["deep"] = True
        return entry
    hits = await feed_hits(session, p)
    if hits:
        entry["feed_hits"] = hits
        entry["signals"].append(Signal("FEED_HIT", 100, f"Link is on known phishing/malware lists ({', '.join(hits)})",
                                       "url", absolute=True, detail=p.host).as_dict())
    cached = (await session.execute(select(Url).where(Url.url_norm == p.url))).scalar_one_or_none()
    s = get_settings()
    if cached and cached.last_checked and as_utc(cached.last_checked) > utcnow() - timedelta(hours=s.url_cache_hours):
        _apply_url_row(entry, cached)
    if st.official and not entry["deep"]:
        entry["deep"] = True   # official destination: nothing to expand
    return entry


def _apply_url_row(entry: dict, row: Url) -> None:
    entry["final"] = row.url_final or entry["final"]
    entry["hops"] = len(row.hops or [])
    entry["screenshot"] = row.screenshot
    entry["signals"] = [s for s in entry["signals"] if s["source"] == "url"] + list(row.deep_signals or [])
    entry["deep"] = True


async def deep_url(session: AsyncSession, entry: dict, rs: RuleSet) -> dict:
    """Expand redirects, check the final URL, RDAP age, sandbox. Stores the result in `urls`."""
    p = parse_url(entry["input"], rs)
    if p is None or p.is_upi:
        entry["deep"] = True
        return entry
    deep: list[Signal] = []
    exp = await net_intel.expand_url(p.url)
    final_raw = exp.final_url
    fp = parse_url(final_raw, rs) or p
    hops = exp.hops
    if len(hops) >= 3 or (exp.cross_domain and len(hops) >= 2):
        deep.append(Signal("REDIRECT_CHAIN", rs.pts("REDIRECT_CHAIN"),
                           f"Link bounces through {len(hops)} addresses before landing on {fp.host}", "deep",
                           detail=fp.host))
    fst = static_url_signals(final_raw, rs) if fp.url != p.url else None
    official = entry.get("official")
    if fst:
        official = fst.official
        for s in fst.signals:
            if s.code in {"LOOKALIKE_DOMAIN", "IP_OR_PUNYCODE_URL", "DOWNLOAD_LINK", "RISKY_TLD", "OFFICIAL_DOMAIN"}:
                deep.append(Signal(s.code, s.points, s.text + " (after redirects)", "deep", detail=s.detail))
        entry["imitates"] = entry.get("imitates") or fst.imitates
        hits = await feed_hits(session, fp)
        if hits:
            entry["feed_hits"] = sorted(set(entry["feed_hits"]) | set(hits))
            deep.append(Signal("FEED_HIT", 100, f"Destination is on known phishing/malware lists ({', '.join(hits)})",
                               "deep", absolute=True, detail=fp.host))
    age = None
    if not official and fp.registered_domain and not fp.is_ip:
        age = await net_intel.domain_age_days(fp.registered_domain)
        if age is not None and age < 30:
            deep.append(Signal("DOMAIN_NEW", rs.pts("DOMAIN_NEW"),
                               f"Website was registered only {age} day{'s' if age != 1 else ''} ago", "deep",
                               detail=fp.registered_domain))
    sb = None
    if not official:
        sb = await sandbox_client.visit(final_raw)
        if sb and not sb.get("error"):
            if any(f.get("password") or f.get("otp") or f.get("card") for f in sb.get("forms", [])):
                deep.append(Signal("LOGIN_FORM", rs.pts("LOGIN_FORM"),
                                   "Page asks for a password, OTP or card details", "deep", detail=sb.get("final_url")))
            if sb.get("download_attempt"):
                deep.append(Signal("DOWNLOAD_ATTEMPT", rs.pts("DOWNLOAD_ATTEMPT"),
                                   "Page tries to download an app or file onto the phone", "deep",
                                   detail=sb.get("final_url")))
            final_raw = sb.get("final_url") or final_raw

    row = (await session.execute(select(Url).where(Url.url_norm == p.url))).scalar_one_or_none()
    if row is None:
        row = Url(url_norm=p.url, host=p.host, registered_domain=p.registered_domain)
        session.add(row)
    row.url_final = final_raw
    row.hops = hops
    row.domain_age_days = age
    row.sandbox = sb
    row.screenshot = (sb or {}).get("screenshot")
    row.deep_signals = [s.as_dict() for s in deep]
    row.last_checked = utcnow()
    _apply_url_row(entry, row)
    entry["host"] = fp.host or entry["host"]
    row.verdict = url_verdict(entry, rs)
    return entry


# ---------------------------------------------------------------- scoring helpers
def rescore(base: list[dict], urls: list[dict], rs: RuleSet) -> ScoreResult:
    sigs = [_sig(d) for d in base]
    for u in urls:
        sigs += [_sig(d) for d in u["signals"]]
    return score(sigs, rs)


def url_verdict(u: dict, rs: RuleSet) -> str:
    return score([_sig(d) for d in u["signals"]], rs).verdict


# ---------------------------------------------------------------- entry points
async def quick_scan(session: AsyncSession, device: Device, body: ScanIn) -> Scan:
    rs = get_ruleset()
    s = get_settings()

    existing = (await session.execute(
        select(Scan).where(Scan.device_id == device.id, Scan.message_id == body.message_id)
    )).scalar_one_or_none()
    if existing:
        return existing

    sender = await upsert_sender(session, body.sender)
    info = classify_sender(body.sender)

    if body.text:
        cs = content_signals(body.text, rs)
        brand_claimed = claims_brand(body.text, rs)
        mentioned = brands_mentioned(body.text, rs)
        raw_urls = list(dict.fromkeys(body.urls + extract_urls(body.text, rs)))
    else:
        cs = signals_from_device_codes(body.local.reasons, rs)
        brand_claimed = "BRAND_CLAIM" in body.local.reasons
        mentioned = []
        raw_urls = list(dict.fromkeys(body.urls))
    ss, header_imp = sender_signals(info, rs, brand_claimed=brand_claimed,
                                    content_codes={c.code for c in cs}, in_contacts=body.features.in_contacts)
    base = [x.as_dict() for x in cs + ss + db_sender_signals(sender, rs)]

    urls = []
    for raw in raw_urls[: s.max_urls_per_message]:
        e = await quick_url(session, raw, rs)
        if e:
            urls.append(e)

    res = rescore(base, urls, rs)
    needs_deep = s.deep_scan_enabled and any(not u["deep"] for u in urls)
    imitated = next((u["imitates"] for u in urls if u.get("imitates")), None) or header_imp or \
        (mentioned[0] if mentioned and res.verdict == "SCAM" else None)

    scan = Scan(
        public_id=str(uuid.uuid4()), device_id=device.id, sender_id=sender.id, message_id=body.message_id,
        text_hash=hashlib.sha256(body.text.encode()).hexdigest() if body.text else None,
        text_enc=encrypt_json({"text": body.text}) if body.text else None,
        received_at=body.received_at.astimezone(UTC) if body.received_at else None, urls=urls,
        features={"base_signals": base, "sim_slot": body.sim_slot, "local": body.local.model_dump(),
                  "in_contacts": body.features.in_contacts, "sender": body.sender},
        signals=[x.as_dict() for x in res.signals], score=res.score, verdict=res.verdict,
        status="partial" if needs_deep else "complete", auto_report=res.auto_report,
        impersonated_brand=imitated,
    )
    session.add(scan)
    if res.verdict == "SCAM":
        await mark_sender_scam(session, sender, device, res.score)
    await session.commit()
    return scan


async def deep_scan(session: AsyncSession, scan_id: int) -> Scan | None:
    rs = get_ruleset()
    scan = await session.get(Scan, scan_id)
    if scan is None:
        return None
    urls = [dict(u) for u in (scan.urls or [])]
    for u in urls:
        if not u["deep"]:
            try:
                await deep_url(session, u, rs)
            except Exception as e:  # one bad URL must not kill the scan
                log.exception("deep analysis failed for a url: %s", e)
                u["deep"] = True
    res = rescore(scan.features["base_signals"], urls, rs)
    scan.urls = urls
    scan.signals = [x.as_dict() for x in res.signals]
    scan.score, scan.verdict, scan.auto_report = res.score, res.verdict, res.auto_report
    scan.impersonated_brand = scan.impersonated_brand or next((u["imitates"] for u in urls if u.get("imitates")), None)
    scan.status = "complete"
    scan.updated_at = utcnow()
    if res.verdict == "SCAM":
        sender = await session.get(Sender, scan.sender_id)
        device = await session.get(Device, scan.device_id)
        await mark_sender_scam(session, sender, device, res.score)
    await session.commit()
    return scan
