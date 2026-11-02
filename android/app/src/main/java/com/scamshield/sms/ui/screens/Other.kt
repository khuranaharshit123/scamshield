package com.scamshield.sms.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import com.scamshield.sms.BuildConfig
import com.scamshield.sms.R
import com.scamshield.sms.container
import com.scamshield.sms.core.network.syncRegistration
import com.scamshield.sms.ui.VerdictChip
import com.scamshield.sms.work.BlocklistSyncWorker
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SimpleScaffold(title: String, onBack: () -> Unit, content: @Composable (Modifier) -> Unit) {
    Scaffold(topBar = {
        TopAppBar(title = { Text(title) },
            navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
    }) { pad -> content(Modifier.padding(pad)) }
}

@Composable
fun NewMessageScreen(initialAddress: String, initialBody: String, onBack: () -> Unit, onSent: (Long) -> Unit) {
    val c = LocalContext.current.container
    val scope = rememberCoroutineScope()
    var to by remember { mutableStateOf(initialAddress) }
    var body by remember { mutableStateOf(initialBody) }
    SimpleScaffold("New message", onBack) { m ->
        Column(m.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(to, { to = it }, label = { Text("To (phone number)") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone), modifier = Modifier.fillMaxWidth())
            OutlinedTextField(body, { body = it }, label = { Text("Message") }, minLines = 3, modifier = Modifier.fillMaxWidth())
            Button(enabled = to.isNotBlank() && body.isNotBlank(), modifier = Modifier.fillMaxWidth(), onClick = {
                scope.launch {
                    val address = to.trim()
                    c.smsSender.send(address, body)
                    onSent(c.sms.threadIdFor(address))
                }
            }) { Text("Send") }
        }
    }
}

@Composable
fun ReportsScreen(onBack: () -> Unit, onOpenThread: (Long) -> Unit) {
    val c = LocalContext.current.container
    val rows by remember { c.db.scanDao().observeReports() }.collectAsState(initial = emptyList())
    SimpleScaffold("Scam reports", onBack) { m ->
        if (rows.isEmpty()) {
            Column(m.fillMaxSize().padding(24.dp)) {
                Text("No reports yet. When a message is confirmed as a scam, the report appears here.")
            }
        } else {
            LazyColumn(m.fillMaxSize()) {
                items(rows, key = { it.messageId }) { r ->
                    Column(Modifier.fillMaxWidth().clickable { onOpenThread(r.threadId) }.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(r.reportId ?: "", style = MaterialTheme.typography.titleSmall)
                            VerdictChip(r.verdict)
                        }
                        Text("From ${r.sender}", style = MaterialTheme.typography.bodyMedium)
                        Text(reportStatusText(r.reportStatus, r.reportMode), style = MaterialTheme.typography.bodySmall)
                    }
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val c = ctx.container
    val scope = rememberCoroutineScope()
    val s by c.settings.flow.collectAsState(initial = null)
    var message by remember { mutableStateOf<String?>(null) }
    val settings = s ?: return
    fun save(block: (com.scamshield.sms.core.data.AppSettings) -> com.scamshield.sms.core.data.AppSettings) {
        scope.launch {
            c.settings.update(block)
            message = syncRegistration(c) ?: "Saved"
        }
    }
    SimpleScaffold("Settings", onBack) { m ->
        Column(m.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Privacy & reporting", style = MaterialTheme.typography.titleMedium)
            ConsentRow(stringResource(R.string.consent_server), settings.consentServer) { v ->
                save { it.copy(consentServer = v, consentAutoReport = it.consentAutoReport && v) }
            }
            ConsentRow(stringResource(R.string.consent_auto_report), settings.consentAutoReport, enabled = settings.consentServer) { v ->
                save { it.copy(consentAutoReport = v) }
            }
            ConsentRow(stringResource(R.string.consent_share_text), settings.shareText, enabled = settings.consentServer) { v ->
                save { it.copy(shareText = v) }
            }
            ConsentRow(stringResource(R.string.consent_1909), settings.auto1909) { v -> save { it.copy(auto1909 = v) } }
            StatePicker(settings.stateCode) { code -> save { it.copy(stateCode = code) } }
            HorizontalDivider()
            Text("Server", style = MaterialTheme.typography.titleMedium)
            Text(BuildConfig.API_BASE_URL, style = MaterialTheme.typography.bodySmall)
            Text(if (settings.deviceToken != null) "Connected" else "Not connected — on-device checks only",
                style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { scope.launch { message = syncRegistration(c) ?: "Connected" } }) { Text("Reconnect") }
                OutlinedButton(onClick = { BlocklistSyncWorker.runNow(ctx); message = "Blocklist update started" }) {
                    Text("Update blocklist")
                }
            }
            message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            HorizontalDivider()
            Text("Rules v${c.ruleSet.version} · app ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.disclaimer), style = MaterialTheme.typography.bodySmall)
        }
    }
}
