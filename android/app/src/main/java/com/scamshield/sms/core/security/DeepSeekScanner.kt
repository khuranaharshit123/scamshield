package com.scamshield.sms.core.security

import android.util.Log
import com.scamshield.sms.BuildConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object DeepSeekScanner {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    fun scanWithDeepSeek(sender: String, text: String, inContacts: Boolean, fallback: LocalScanResult): LocalScanResult {
        val apiKey = BuildConfig.DEEPSEEK_API_KEY
        if (apiKey.isEmpty()) return fallback

        val signals = fallback.score.signals
        // Blocklisted sender / known phishing link: hard evidence, the AI must not second-guess it.
        if (signals.any { it.absolute }) return fallback
        val officialLink = signals.any { it.code == "OFFICIAL_DOMAIN" || it.code == "GOV_HEADER" } &&
            signals.none { it.code == "LOOKALIKE_DOMAIN" }
        val senderType = "type=${fallback.sender.kind}" +
            (fallback.sender.header?.let { ", registered header=$it" } ?: "")
        val evidence = if (signals.isEmpty()) "none" else signals.joinToString("; ") { "${it.code}: ${it.text}" }

        val prompt = """
            Classify the following SMS message as SCAM, SUSPICIOUS or SAFE.
            On-device checks found: $evidence
            Sender details: $senderType
            Instructions:
            0. Trust the on-device checks. OFFICIAL_DOMAIN means the link goes to a verified official site, so that link alone is not a scam. LOOKALIKE_DOMAIN means a fake imitation site, which is a strong scam sign. A sender ID like VM-SBIINB (2 letters, dash, name) is a registered business header and is more trustworthy than a plain 10-digit number.
            1. The sender is ${if (inContacts) "SAVED in the user's contacts (a known person)" else "NOT in the user's contacts (unknown)"}.
            2. SCAM requires concrete evidence of an attack: a link, a phone number to call back, a request for OTP/PIN/password/card/Aadhaar details, a request to send or pay money, or impersonation of a bank, government body or company with a threat.
            3. A short or vague message with none of the above (e.g. "Electricity disconnected", "KYC pending") is NOT a scam by itself: answer SUSPICIOUS if the sender is unknown, SAFE if the sender is a known contact.
            4. Casual personal chat (Hindi/Hinglish slang like "bhai", "yaar", "jaldi kar le") with no link and no request for secrets or money is SAFE.
            5. Consider Hinglish text carefully.

            Sender: $sender
            Message: $text

            Return ONLY one word: SCAM, SUSPICIOUS or SAFE.
        """.trimIndent()

        val jsonBody = JSONObject().apply {
            put("model", "deepseek-chat")
            put("messages", JSONArray().apply {
                put(JSONObject().apply {
                    put("role", "user")
                    put("content", prompt)
                })
            })
            put("temperature", 0.0)
        }

        val request = Request.Builder()
            .url("https://api.deepseek.com/chat/completions")
            .addHeader("Authorization", "Bearer ${"$apiKey"}")
            .addHeader("Content-Type", "application/json")
            .post(jsonBody.toString().toRequestBody("application/json".toMediaType()))
            .build()

        return try {
            val response = client.newCall(request).execute()
            val responseBody = response.body?.string() ?: ""
            Log.d("DeepSeekScanner", "Response: $responseBody")

            if (response.isSuccessful) {
                val jsonResponse = JSONObject(responseBody)
                val content = jsonResponse.getJSONArray("choices")
                    .getJSONObject(0)
                    .getJSONObject("message")
                    .getString("content").trim().uppercase()

                Log.d("DeepSeekScanner", "Parsed content: $content")

                if (content.contains("SUSPICIOUS")) {
                    fallback.copy(score = fallback.score.copy(verdict = Verdict.SUSPICIOUS), aiVerdict = Verdict.SUSPICIOUS)
                } else if (content.contains("SCAM") && officialLink) {
                    // verified official link: never hard-flag, leave the user a caution only
                    fallback.copy(score = fallback.score.copy(verdict = Verdict.SUSPICIOUS), aiVerdict = Verdict.SUSPICIOUS)
                } else if (content.contains("SCAM")) {
                    fallback.copy(score = fallback.score.copy(verdict = Verdict.SCAM), aiVerdict = Verdict.SCAM)
                } else if (content.contains("SAFE")) {
                    fallback.copy(score = fallback.score.copy(verdict = Verdict.SAFE), aiVerdict = Verdict.SAFE)
                } else {
                    fallback
                }
            } else {
                Log.e("DeepSeekScanner", "API Error: ${response.code} $responseBody")
                fallback
            }
        } catch (e: Exception) {
            Log.e("DeepSeekScanner", "Error analyzing with DeepSeek", e)
            fallback
        }
    }
}
