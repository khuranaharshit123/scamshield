package com.scamshield.sms.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Telephony
import android.text.format.DateFormat
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.BorderStroke
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.scamshield.sms.container
import com.scamshield.sms.core.data.ScanResultEntity
import com.scamshield.sms.core.telephony.SmsMessage
import com.scamshield.sms.ui.ScamRed
import com.scamshield.sms.ui.VerdictChip
import com.scamshield.sms.ui.verdictColor
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreadScreen(threadId: Long, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val c = ctx.container
    val scope = rememberCoroutineScope()
    val messages by remember(threadId) { c.sms.observeThread(threadId) }.collectAsState(initial = emptyList())
    val scans by remember(threadId) { c.db.scanDao().observeThread(threadId) }.collectAsState(initial = emptyList())
    val scanMap = remember(scans) { scans.associateBy { it.messageId } }
    val address = messages.firstOrNull()?.address.orEmpty()
    val name = remember(address) { if (address.isNotEmpty()) c.sms.contactName(address) else null }
    var detailsFor by remember { mutableStateOf<ScanResultEntity?>(null) }
    var confirmBlock by remember { mutableStateOf(false) }
    var confirmDeleteChat by remember { mutableStateOf(false) }
    var actionsFor by remember { mutableStateOf<SmsMessage?>(null) }
    var confirmDeleteMsg by remember { mutableStateOf<SmsMessage?>(null) }
    val senderNorm = remember(address) { com.scamshield.sms.core.security.SenderAnalyzer.classify(address).norm }
    val trusted by remember(senderNorm) { c.db.trustedDao().observeTrusted(senderNorm) }.collectAsState(initial = false)
    val listState = rememberLazyListState()

    LaunchedEffect(threadId, messages.size) {
        c.sms.markThreadRead(threadId)
        c.notifier.cancel(threadId)
        if (messages.isNotEmpty()) listState.scrollToItem(messages.lastIndex)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(name ?: address, maxLines = 1) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
                actions = {
                    if (trusted) {
                        // Marked safe earlier; tap to go back to normal scanning for new messages.
                        IconButton(onClick = {
                            scope.launch {
                                c.db.trustedDao().remove(senderNorm)
                                android.widget.Toast.makeText(ctx, "No longer trusted. New messages will be scanned.",
                                    android.widget.Toast.LENGTH_SHORT).show()
                            }
                        }) { Icon(Icons.Default.VerifiedUser, "Stop trusting this sender") }
                    }
                    IconButton(onClick = { confirmDeleteChat = true }) { Icon(Icons.Default.Delete, "Delete conversation") }
                    if (address.isNotEmpty() && c.sms.canBlock()) {
                        IconButton(onClick = { confirmBlock = true }) { Icon(Icons.Default.Block, "Block sender") }
                    }
                },
            )
        },
        bottomBar = { if (address.isNotEmpty()) Composer(address) },
    ) { pad ->
        LazyColumn(
            Modifier.padding(pad).fillMaxSize(), state = listState,
            verticalArrangement = Arrangement.spacedBy(6.dp),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        ) {
            items(messages, key = { it.id }) { m ->
                Bubble(m, scanMap[m.id], onWhy = { detailsFor = it }, onLongPress = { actionsFor = m })
            }
        }
    }

    detailsFor?.let { scan -> ScanDetailsSheet(scan, address, onDismiss = { detailsFor = null }) }

    actionsFor?.let { m ->
        AlertDialog(
            onDismissRequest = { actionsFor = null },
            title = { Text("Message") },
            confirmButton = {
                TextButton(onClick = { confirmDeleteMsg = m; actionsFor = null }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { copy(ctx, m.body); actionsFor = null }) { Text("Copy") }
            },
        )
    }

    confirmDeleteMsg?.let { m ->
        AlertDialog(
            onDismissRequest = { confirmDeleteMsg = null },
            title = { Text("Delete this message?") },
            text = { Text("It will be removed from your phone.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDeleteMsg = null
                    scope.launch {
                        val n = runCatching { c.sms.deleteMessage(m.id) }.getOrDefault(0)
                        if (n == 0) deleteFailed(ctx)
                    }
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDeleteMsg = null }) { Text("Cancel") } },
        )
    }

    if (confirmDeleteChat) {
        AlertDialog(
            onDismissRequest = { confirmDeleteChat = false },
            title = { Text("Delete this conversation?") },
            text = { Text("All messages with ${name ?: address} will be removed from your phone.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDeleteChat = false
                    scope.launch {
                        val n = runCatching { c.sms.deleteThread(threadId) }.getOrDefault(0)
                        if (n == 0) deleteFailed(ctx) else onBack()
                    }
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDeleteChat = false }) { Text("Cancel") } },
        )
    }

    if (confirmBlock) {
        AlertDialog(
            onDismissRequest = { confirmBlock = false },
            title = { Text("Block $address?") },
            text = { Text("Android will stop delivering messages and calls from this sender.") },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch { c.sms.block(address) }
                    confirmBlock = false
                }) { Text("Block") }
            },
            dismissButton = { TextButton(onClick = { confirmBlock = false }) { Text("Cancel") } },
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun Bubble(m: SmsMessage, scan: ScanResultEntity?, onWhy: (ScanResultEntity) -> Unit, onLongPress: () -> Unit) {
    val ctx = LocalContext.current
    val mine = !m.incoming
    val danger = scan?.verdict == "SCAM" || scan?.verdict == "SUSPICIOUS"
    Column(Modifier.fillMaxWidth(), horizontalAlignment = if (mine) Alignment.End else Alignment.Start) {
        if (scan != null && danger) {
            Surface(
                color = verdictColor(scan.verdict).copy(alpha = 0.12f),
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.widthIn(max = 320.dp).combinedClickable(onClick = { onWhy(scan) }),
            ) {
                Row(Modifier.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Warning, null, tint = verdictColor(scan.verdict))
                    Text(
                        if (scan.verdict == "SCAM") "Likely scam — don't tap links, call back or share OTPs. Tap for why."
                        else "Be careful with this message. Tap for why.",
                        style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(start = 6.dp),
                    )
                }
            }
            Spacer(Modifier.heightIn(4.dp))
        }
        Surface(
            color = if (mine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
            shape = RoundedCornerShape(16.dp),
            border = if (scan?.verdict == "SCAM") BorderStroke(1.5.dp, ScamRed) else null,
            modifier = Modifier.widthIn(max = 320.dp).combinedClickable(
                onClick = { if (scan != null) onWhy(scan) },
                onLongClick = onLongPress,
            ),
        ) {
            Column(Modifier.padding(10.dp)) {
                // Links are shown as plain text on purpose: nothing in a message is tappable.
                Text(m.body, style = MaterialTheme.typography.bodyLarge)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        DateFormat.format("dd MMM, HH:mm", m.date).toString() + statusSuffix(m),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (!mine) {
                        Spacer(Modifier.widthIn(6.dp))
                        VerdictChip(scan?.verdict)
                    }
                }
            }
        }
    }
}

private fun statusSuffix(m: SmsMessage): String = when (m.type) {
    Telephony.Sms.MESSAGE_TYPE_OUTBOX, Telephony.Sms.MESSAGE_TYPE_QUEUED -> " · sending"
    Telephony.Sms.MESSAGE_TYPE_FAILED -> " · failed"
    Telephony.Sms.MESSAGE_TYPE_SENT -> if (m.status == Telephony.Sms.STATUS_COMPLETE) " · delivered" else " · sent"
    else -> ""
}

private fun copy(ctx: Context, text: String) {
    ctx.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("sms", text))
}

@Composable
private fun Composer(address: String) {
    val c = LocalContext.current.container
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    val sims = remember { c.smsSender.activeSims() }
    var subId by remember { mutableStateOf(sims.firstOrNull()?.subscriptionId ?: c.smsSender.defaultSubId()) }
    var simMenu by remember { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().imePadding().navigationBarsPadding().padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (sims.size > 1) {
            TextButton(onClick = { simMenu = true }) {
                Text("SIM ${sims.indexOfFirst { it.subscriptionId == subId } + 1}")
            }
            DropdownMenu(simMenu, onDismissRequest = { simMenu = false }) {
                sims.forEachIndexed { i, s ->
                    DropdownMenuItem(text = { Text("SIM ${i + 1} · ${s.displayName}") },
                        onClick = { subId = s.subscriptionId; simMenu = false })
                }
            }
        }
        OutlinedTextField(
            value = text, onValueChange = { text = it }, modifier = Modifier.weight(1f),
            placeholder = { Text("Text message") }, maxLines = 5,
            supportingText = if (text.length > 140) {
                { Text("${c.smsSender.partsCount(text)} SMS") }
            } else null,
        )
        IconButton(enabled = text.isNotBlank(), onClick = {
            val body = text
            text = ""
            scope.launch { c.smsSender.send(address, body, subId) }
        }) { Icon(Icons.AutoMirrored.Filled.Send, "Send") }
    }
}

fun openUrl(ctx: Context, url: String) {
    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}

private fun deleteFailed(ctx: android.content.Context) = android.widget.Toast.makeText(
    ctx, "Couldn't delete. ScamShield must be your default SMS app.", android.widget.Toast.LENGTH_LONG,
).show()
