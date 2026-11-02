package com.scamshield.sms.core.security

import android.util.Log
import com.google.ai.client.generativeai.GenerativeModel
import com.google.ai.client.generativeai.type.content
import com.scamshield.sms.BuildConfig
import kotlinx.coroutines.runBlocking

object GeminiScanner {
    fun scanWithGemini(sender: String, text: String, fallback: LocalScanResult): LocalScanResult {
        val apiKey = BuildConfig.GEMINI_API_KEY
        if (apiKey.isEmpty()) return fallback

        // Using gemini-1.5-flash as the standard fallback, as some regions haven't
        // rolled out latest/8b on the SDK level yet.
        val generativeModel = GenerativeModel(
            modelName = "gemini-1.5-flash",
            apiKey = apiKey
        )

        val prompt = """
            Analyze the following SMS message to determine if it is a SCAM or SAFE.
            Also consider Hinglish text (Hindi written in English alphabets) like 'kyc', 'bank', etc.
            Sender: $sender
            Message: $text
            
            Return ONLY the word SCAM or SAFE.
        """.trimIndent()

        return try {
            val response = runBlocking {
                generativeModel.generateContent(prompt)
            }
            val textResponse = response.text?.trim()?.uppercase() ?: ""
            Log.d("GeminiScanner", "Response: $textResponse")
            if (textResponse.contains("SCAM")) {
                val newScore = fallback.score.copy(verdict = Verdict.SCAM)
                fallback.copy(score = newScore)
            } else if (textResponse.contains("SAFE")) {
                val newScore = fallback.score.copy(verdict = Verdict.SAFE)
                fallback.copy(score = newScore)
            } else {
                fallback
            }
        } catch (e: Exception) {
            Log.e("GeminiScanner", "Error analyzing with Gemini", e)
            fallback
        }
    }
}