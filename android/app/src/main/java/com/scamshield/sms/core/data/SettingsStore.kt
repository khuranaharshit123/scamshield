package com.scamshield.sms.core.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "settings")

data class AppSettings(
    val onboarded: Boolean = false,
    val deviceToken: String? = null,
    val stateCode: String? = null,
    val consentVersion: Int = 0,
    val consentServer: Boolean = false,
    val consentAutoReport: Boolean = false,
    val shareText: Boolean = false,
    val auto1909: Boolean = false,
    val reporterName: String? = null,
    val reporterPhone: String? = null,
    val blocklistVersion: String? = null,
)

class SettingsStore(private val context: Context) {
    private object K {
        val onboarded = booleanPreferencesKey("onboarded")
        val token = stringPreferencesKey("device_token")
        val state = stringPreferencesKey("state_code")
        val consentVersion = intPreferencesKey("consent_version")
        val consentServer = booleanPreferencesKey("consent_server")
        val consentAuto = booleanPreferencesKey("consent_auto_report")
        val shareText = booleanPreferencesKey("share_text")
        val auto1909 = booleanPreferencesKey("auto_1909")
        val name = stringPreferencesKey("reporter_name")
        val phone = stringPreferencesKey("reporter_phone")
        val blVersion = stringPreferencesKey("blocklist_version")
    }

    val flow: Flow<AppSettings> = context.dataStore.data.map { it.toSettings() }

    suspend fun snapshot(): AppSettings = flow.first()

    private fun Preferences.toSettings() = AppSettings(
        onboarded = this[K.onboarded] ?: false,
        deviceToken = this[K.token],
        stateCode = this[K.state],
        consentVersion = this[K.consentVersion] ?: 0,
        consentServer = this[K.consentServer] ?: false,
        consentAutoReport = this[K.consentAuto] ?: false,
        shareText = this[K.shareText] ?: false,
        auto1909 = this[K.auto1909] ?: false,
        reporterName = this[K.name],
        reporterPhone = this[K.phone],
        blocklistVersion = this[K.blVersion],
    )

    suspend fun update(block: (AppSettings) -> AppSettings) {
        context.dataStore.edit { p ->
            val s = block(p.toSettings())
            p[K.onboarded] = s.onboarded
            s.deviceToken?.let { p[K.token] = it } ?: p.remove(K.token)
            s.stateCode?.let { p[K.state] = it } ?: p.remove(K.state)
            p[K.consentVersion] = s.consentVersion
            p[K.consentServer] = s.consentServer
            p[K.consentAuto] = s.consentAutoReport
            p[K.shareText] = s.shareText
            p[K.auto1909] = s.auto1909
            s.reporterName?.let { p[K.name] = it } ?: p.remove(K.name)
            s.reporterPhone?.let { p[K.phone] = it } ?: p.remove(K.phone)
            s.blocklistVersion?.let { p[K.blVersion] = it } ?: p.remove(K.blVersion)
        }
    }
}
