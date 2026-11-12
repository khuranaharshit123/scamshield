package com.scamshield.sms.core.security

/** Mirrors backend/app/services/scorer.py. */
data class ScoreResult(
    val score: Int,
    val verdict: Verdict,
    val autoReport: Boolean,
    val signals: List<Signal>,
)

object Scorer {
    // A saved contact can't be a "scam", but real scam wording from one (hacked phone, spoofed number) is
    // still flagged: SUSPICIOUS with a deliberately low score. Mirrored in scorer.py.
    const val CONTACT_FLAG_MIN = 15
    private val CONTACT_SCORE_RANGE = 10..25

    fun dedupe(signals: List<Signal>): List<Signal> {
        val best = LinkedHashMap<String, Signal>()
        for (s in signals) {
            val cur = best[s.code]
            if (cur == null || compareValuesBy(s, cur, { it.absolute }, { kotlin.math.abs(it.points) }) > 0) {
                best[s.code] = s
            }
        }
        return best.values.sortedWith(compareBy<Signal>({ !it.absolute }, { -it.points }))
    }

    fun score(signals: List<Signal>, rs: RuleSet): ScoreResult {
        val sigs = dedupe(signals)
        val absolute = sigs.any { it.absolute }
        val weak = minOf(sigs.filter { it.code in WEAK_CODES && it.points > 0 }.sumOf { it.points }, rs.weakSignalCap)
        val grouped = HashMap<String, Int>()
        var strong = 0
        for (s in sigs) {
            if (s.code in WEAK_CODES || s.points <= 0) continue
            if (s.group != null) grouped[s.group] = maxOf(grouped[s.group] ?: 0, s.points) else strong += s.points
        }
        strong += grouped.values.sum()
        // Trust signals only help when nothing strong is wrong, so a spoofed header/link can't mask a scam.
        val trust = setOf("OFFICIAL_DOMAIN", "GOV_HEADER")
        var negative = sigs.filter { it.points < 0 && it.code !in trust }.sumOf { it.points }
        if (strong == 0) negative += sigs.filter { it.code in trust }.sumOf { it.points }
        val contactFlag = !absolute && strong >= CONTACT_FLAG_MIN && sigs.any { it.code == "IN_CONTACTS" }
        val total = if (absolute) 100 else (strong + weak + negative).coerceIn(0, 100)
            .let { if (contactFlag) it.coerceIn(CONTACT_SCORE_RANGE) else it }
        val verdict = when {
            contactFlag -> Verdict.SUSPICIOUS
            total >= rs.thresholdScam -> Verdict.SCAM
            total >= rs.thresholdSuspicious -> Verdict.SUSPICIOUS
            else -> Verdict.SAFE
        }
        val auto = verdict == Verdict.SCAM && (absolute || total >= rs.thresholdAutoReport)
        val shown = sigs.filter { it.points != 0 || it.absolute || it.code == "UPI_LINK" }
        return ScoreResult(total, verdict, auto, shown)
    }
}

/** What the phone knows offline: blocked senders and blocked domain hashes synced from the server. */
interface BlocklistLookup {
    fun isSenderBlocked(senderNorm: String): Boolean
    fun isDomainBlocked(domainHash: String): Boolean

    object Empty : BlocklistLookup {
        override fun isSenderBlocked(senderNorm: String) = false
        override fun isDomainBlocked(domainHash: String) = false
    }
}

data class LocalScanResult(
    val sender: SenderInfo,
    val score: ScoreResult,
    val urls: List<String>,
    /** Codes sent to the server when the message text is NOT shared (privacy default). */
    val reasonCodes: List<String>,
    val impersonatedBrand: String?,
    /** Verdict from the AI second opinion, null when it was unavailable or inconclusive. */
    val aiVerdict: Verdict? = null,
)

/** On-device first pass (context file §4.4). Runs in ≪ 50 ms, no network. */
class LocalScanner(private val rs: RuleSet, private val blocklist: BlocklistLookup = BlocklistLookup.Empty) {

    fun scan(sender: String, text: String, inContacts: Boolean = false): LocalScanResult {
        val info = SenderAnalyzer.classify(sender)
        val content = ContentRules.signals(text, rs)
        val brandClaimed = ContentRules.claimsBrand(text, rs)
        val senderRes = SenderAnalyzer.signals(info, rs, brandClaimed, content.map { it.code }.toSet(), inContacts)
        val all = content.toMutableList()
        all += senderRes.signals
        if (blocklist.isSenderBlocked(info.norm)) {
            all += Signal("SENDER_BLOCKED", 100, "This sender is on the ScamShield blocklist", "db",
                absolute = true, detail = info.norm)
        }
        val urls = UrlAnalyzer.extract(text, rs)
        var imitates: String? = null
        for (u in urls) {
            val st = UrlAnalyzer.staticSignals(u, rs) ?: continue
            all += st.signals
            imitates = imitates ?: st.imitates
            val p = st.parsed
            if (!p.isUpi && p.host.isNotEmpty() &&
                (blocklist.isDomainBlocked(TextUtils.domainHash(p.registeredDomain)) ||
                    blocklist.isDomainBlocked(TextUtils.domainHash(p.host)))
            ) {
                all += Signal("FEED_HIT", 100, "Link is on known phishing/malware lists", "url",
                    absolute = true, detail = p.host)
            }
        }
        val result = Scorer.score(all, rs)
        val codes = content.map { it.code }.toMutableList()
        if (brandClaimed) codes += "BRAND_CLAIM"
        return LocalScanResult(info, result, urls, codes, imitates ?: senderRes.impersonated)
    }
}
