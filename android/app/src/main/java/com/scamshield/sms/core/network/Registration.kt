package com.scamshield.sms.core.network

import com.scamshield.sms.AppContainer
import com.scamshield.sms.BuildConfig

/**
 * Registers the device (first time) or pushes updated consent/state (later).
 * Returns null on success, or a human-readable error. The app keeps working on-device either way.
 */
suspend fun syncRegistration(c: AppContainer): String? {
    val s = c.settings.snapshot()
    // Never registered and no consent → nothing to send (on-device protection only).
    // Already registered → always push, so withdrawn consent reaches the server too.
    if (!s.consentServer && s.deviceToken == null) return null
    val body = RegisterIn(
        appVersion = BuildConfig.VERSION_NAME,
        stateCode = s.stateCode,
        consentVersion = s.consentVersion,
        consentServerCheck = s.consentServer,
        consentAutoReport = s.consentAutoReport,
        reporterName = s.reporterName,
        reporterPhone = s.reporterPhone,
    )
    return try {
        if (s.deviceToken == null) {
            val out = c.api.service.register(body)
            c.settings.update { it.copy(deviceToken = out.deviceToken) }
        } else {
            val r = c.api.service.updateConsent(body)
            if (r.code() == 401) { // server forgot us (DB reset) → register again
                c.settings.update { it.copy(deviceToken = null) }
                return syncRegistration(c)
            }
        }
        null
    } catch (e: Exception) {
        "Server not reachable (${e.javaClass.simpleName}). On-device protection is active; retry from Settings."
    }
}
