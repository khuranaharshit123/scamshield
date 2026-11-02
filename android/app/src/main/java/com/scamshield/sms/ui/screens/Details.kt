package com.scamshield.sms.ui.screens

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import com.scamshield.sms.container
import com.scamshield.sms.core.data.ScanResultEntity
import com.scamshield.sms.core.network.FeedbackIn
import com.scamshield.sms.core.network.Portal
import com.scamshield.sms.core.network.Reason
import com.scamshield.sms.core.network.UrlOut
import com.scamshield.sms.ui.VerdictChip
import com.scamshield.sms.ui.verdictColor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

private val DEFAULT_PORTALS = listOf(
    Portal("ncrp", "National Cyber Crime Reporting Portal — Report Suspect", "https://cybercrime.gov.in"),
    Portal("chakshu", "Sanchar Saathi — Chakshu", "https://sancharsaathi.gov.in/sfc/"),
    Portal("helpline", "Lost money? Call 1930", "tel:1930"),
)

/** "Why was this flagged?" — score, reasons, link analysis, report status, next steps. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanDetailsSheet(scan: ScanResultEntity, address: String, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val c = ctx.container
    val json = c.api.json
    val scope = rememberCoroutineScope()
    val reasons = remember(scan) { runCatching { json.decodeFromString(ListSerializer(Reason.serializer()), scan.reasonsJson) }.getOrDefault(emptyList()) }
    val urls = remember(scan) { runCatching { json.decodeFromString(ListSerializer(UrlOut.serializer()), scan.urlsJson) }.getOrDefault(emptyList()) }
    val portals = remember(scan) {
        scan.portalsJson?.let { runCatching { json.decodeFromString(ListSerializer(Portal.serializer()), it) }.getOrNull() }
            ?.takeIf { it.isNotEmpty() } ?: DEFAULT_PORTALS
    }
    val intended = remember(scan) {
        scan.reportIntendedJson?.let { runCatching { json.decodeFromString(ListSerializer(JsonObject.serializer()), it) }.getOrNull() }
            .orEmpty().mapNotNull { it["label"]?.jsonPrimitive?.content }.distinct()
    }
    var feedbackSent by remember { mutableStateOf(scan.feedback) }
    var showReportDialog by remember { mutableStateOf(false) }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                VerdictChip(scan.verdict)
                Text("Risk ${scan.score}/100", fontWeight = FontWeight.SemiBold, color = verdictColor(scan.verdict))
                if (scan.status != "COMPLETE") Text("· checking links…", style = MaterialTheme.typography.bodySmall)
            }
            Text("Why", style = MaterialTheme.typography.titleMedium)
            if (reasons.isEmpty()) Text("No warning signs found.")
            reasons.forEach { r ->
                Text("• ${r.text}" + (r.detail?.let { " ($it)" } ?: ""), style = MaterialTheme.typography.bodyMedium)
            }

            if (urls.isNotEmpty()) {
                HorizontalDivider()
                Text("Links (opened in our sandbox, not on your phone)", style = MaterialTheme.typography.titleMedium)
                urls.forEach { u ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(u.input, style = MaterialTheme.typography.bodySmall)
                            if (u.final != null && u.final != u.input) Text("→ ends at ${u.final}", style = MaterialTheme.typography.bodySmall)
                            if (u.hops > 1) Text("${u.hops} redirect steps", style = MaterialTheme.typography.labelSmall)
                            if (u.feedHits.isNotEmpty()) Text("Listed by: ${u.feedHits.joinToString()}",
                                color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                            u.screenshotUrl?.let {
                                AsyncImage(model = it, contentDescription = "Sandbox screenshot of the page",
                                    contentScale = ContentScale.FillWidth, modifier = Modifier.fillMaxWidth().heightIn(max = 360.dp))
                            }
                        }
                    }
                }
            }

            if (scan.reportId != null) {
                HorizontalDivider()
                Text("Report ${scan.reportId}", style = MaterialTheme.typography.titleMedium)
                Text(reportStatusText(scan.reportStatus, scan.reportMode))
                if (intended.isNotEmpty()) Text("Recipients: ${intended.joinToString()}", style = MaterialTheme.typography.bodySmall)
            }

            if (scan.verdict != "SAFE") {
                HorizontalDivider()
                Text("What you can do", style = MaterialTheme.typography.titleMedium)
                Button(
                    onClick = { showReportDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError
                    ),
                ) {
                    Text("✉ Email Report to Authority")
                }
                portals.forEach { p ->
                    OutlinedButton(onClick = { openUrl(ctx, p.url) }, modifier = Modifier.fillMaxWidth()) { Text(p.label) }
                }
            }

            HorizontalDivider()
            if (scan.verdict != "SAFE") {
                Button(onClick = {
                    scope.launch {
                        val norm = com.scamshield.sms.core.security.SenderAnalyzer.classify(scan.sender).norm
                        c.db.trustedDao().add(com.scamshield.sms.core.data.TrustedSender(norm))
                        c.db.scanDao().upsert(scan.copy(verdict = "SAFE", score = 0, feedback = "not_scam",
                            updatedAt = System.currentTimeMillis()))
                        scan.serverScanId?.let { runCatching { c.api.service.feedback(FeedbackIn(it, "not_scam")) } }
                    }
                    onDismiss()
                }, modifier = Modifier.fillMaxWidth()) { Text("Mark sender as safe") }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = scan.serverScanId != null && feedbackSent == null, onClick = {
                    val label = if (scan.verdict == "SAFE") "scam" else "not_scam"
                    scope.launch {
                        runCatching { c.api.service.feedback(FeedbackIn(scan.serverScanId!!, label)) }
                        c.db.scanDao().upsert(scan.copy(feedback = label))
                        feedbackSent = label
                    }
                }) { Text(if (feedbackSent != null) "Thanks!" else if (scan.verdict == "SAFE") "This is a scam" else "Not a scam") }
                if (c.sms.canBlock() && address.isNotEmpty()) {
                    OutlinedButton(onClick = { scope.launch { c.sms.block(address) }; onDismiss() }) { Text("Block sender") }
                }
            }
            Text("Automated checks can be wrong. A warning is not a legal finding.", style = MaterialTheme.typography.bodySmall)
        }
    }

    if (showReportDialog) {
        ReportEmailDialog(
            scan = scan,
            reasons = reasons,
            urls = urls,
            onDismiss = { showReportDialog = false }
        )
    }
}

data class AuthorityOption(val name: String, val email: String)

private val AUTHORITIES = listOf(
    AuthorityOption("Punjab State Cyber Crime Cell", "adgp.statecybercrime@punjabpolice.gov.in"),
    AuthorityOption("Delhi Police Cyber Crime (IFSO)", "cybercell-delhi@nic.in"),
    AuthorityOption("National Cyber Crime Reporting", "complaint-cybercrime@gov.in"),
    AuthorityOption("Haryana Cyber Crime", "cybercell.haryana@hry.nic.in"),
    AuthorityOption("Custom / Other Email", ""),
)

@Composable
fun ReportEmailDialog(
    scan: ScanResultEntity,
    reasons: List<Reason>,
    urls: List<UrlOut>,
    onDismiss: () -> Unit,
) {
    val ctx = LocalContext.current
    val c = ctx.container
    val scope = rememberCoroutineScope()
    var expanded by remember { mutableStateOf(false) }
    var selectedAuthority by remember { mutableStateOf(AUTHORITIES[0]) }
    var customEmail by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Report to Cyber Crime Cell") },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    "Choose an authority to report this SMS to. This will prepare a draft in your email app (Gmail, etc.) so you can review and send it manually.",
                    style = MaterialTheme.typography.bodySmall
                )
                Box(modifier = Modifier.fillMaxWidth()) {
                    OutlinedCard(
                        onClick = { expanded = true },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(14.dp).fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Authority Recipient", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                                Text(selectedAuthority.name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                                if (selectedAuthority.email.isNotEmpty()) {
                                    Text(selectedAuthority.email, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                            Text("▼", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                        }
                    }
                    DropdownMenu(
                        expanded = expanded,
                        onDismissRequest = { expanded = false },
                        modifier = Modifier.fillMaxWidth(0.85f)
                    ) {
                        AUTHORITIES.forEach { auth ->
                            DropdownMenuItem(
                                text = {
                                    Column {
                                        Text(auth.name, fontWeight = FontWeight.Medium)
                                        if (auth.email.isNotEmpty()) {
                                            Text(auth.email, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                        }
                                    }
                                },
                                onClick = {
                                    selectedAuthority = auth
                                    expanded = false
                                }
                            )
                        }
                    }
                }
                if (selectedAuthority.email.isEmpty()) {
                    OutlinedTextField(
                        value = customEmail,
                        onValueChange = { customEmail = it },
                        label = { Text("Enter Authority Email") },
                        placeholder = { Text("e.g. officer@police.gov.in") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                val targetEmail = if (selectedAuthority.email.isNotEmpty()) selectedAuthority.email else customEmail.trim()
                if (targetEmail.isEmpty() || !targetEmail.contains("@")) {
                    Toast.makeText(ctx, "Please enter a valid email address", Toast.LENGTH_SHORT).show()
                    return@Button
                }
                scope.launch(Dispatchers.IO) {
                    val msgBody = c.sms.message(scan.messageId)?.body ?: ""
                    withContext(Dispatchers.Main) {
                        sendEmailReport(
                            ctx = ctx,
                            recipientEmail = targetEmail,
                            sender = scan.sender,
                            bodyText = msgBody,
                            verdict = scan.verdict,
                            score = scan.score,
                            reasons = reasons,
                            urls = urls
                        )
                        onDismiss()
                    }
                }
            }) {
                Text("Draft Email in App")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

fun sendEmailReport(
    ctx: Context,
    recipientEmail: String,
    sender: String,
    bodyText: String,
    verdict: String,
    score: Int,
    reasons: List<Reason>,
    urls: List<UrlOut>,
) {
    val subject = "[ScamShield Report] Suspected Scam SMS from $sender"
    val reportText = buildString {
        appendLine("To: Cyber Crime Cell / Fraud Reporting Authority")
        appendLine()
        appendLine("I am reporting a suspicious / fraudulent SMS message received on my mobile device.")
        appendLine()
        appendLine("--- MESSAGE DETAILS ---")
        appendLine("Sender: $sender")
        if (bodyText.isNotBlank()) {
            appendLine("Message Content:")
            appendLine("\"$bodyText\"")
        }
        appendLine()
        appendLine("--- SCAMSHIELD DETECTION ANALYSIS ---")
        appendLine("Verdict: $verdict (Risk Score: $score/100)")
        if (reasons.isNotEmpty()) {
            appendLine("Warning Signs Detected:")
            reasons.forEach { r ->
                appendLine(" • ${r.text}${if (r.detail != null) " (${r.detail})" else ""}")
            }
        }
        if (urls.isNotEmpty()) {
            appendLine()
            appendLine("Extracted Links:")
            urls.forEach { u ->
                val red = if (u.final != null && u.final != u.input) " -> ${u.final}" else ""
                val hits = if (u.feedHits.isNotEmpty()) " [Listed on: ${u.feedHits.joinToString()}]" else ""
                appendLine(" • ${u.input}$red$hits")
            }
        }
        appendLine()
        appendLine("---")
        appendLine("Prepared by ScamShield for manual user review and submission.")
    }

    val intent = Intent(Intent.ACTION_SENDTO).apply {
        data = Uri.parse("mailto:")
        putExtra(Intent.EXTRA_EMAIL, arrayOf(recipientEmail))
        putExtra(Intent.EXTRA_SUBJECT, subject)
        putExtra(Intent.EXTRA_TEXT, reportText)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    runCatching {
        ctx.startActivity(Intent.createChooser(intent, "Send Report via Email"))
    }.onFailure {
        Toast.makeText(ctx, "No email app found on device", Toast.LENGTH_SHORT).show()
    }
}

fun reportStatusText(status: String?, mode: String?): String = when (status) {
    "awaiting_log" -> "Preparing report…"
    "queued" -> "Report queued"
    "sent" -> "Sent to the authorities"
    "demo_sent" -> "Demo report sent to the team inbox (demo mode — authorities were not emailed)"
    "duplicate" -> "Already reported (same sender and link) — added to the earlier report"
    "no_recipient" -> "No verified authority address for your state yet"
    "failed" -> "Sending failed — the server will retry"
    "disabled" -> "Automatic reports are switched off on the server"
    else -> status ?: "—"
} + if (mode == "demo" && status != "demo_sent") " (demo mode)" else ""
