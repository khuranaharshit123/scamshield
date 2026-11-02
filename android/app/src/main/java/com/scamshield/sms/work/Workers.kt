package com.scamshield.sms.work

import android.content.Context
import android.content.pm.ServiceInfo
import android.os.Build
import android.provider.Telephony
import com.scamshield.sms.core.security.Verdict
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.scamshield.sms.container
import com.scamshield.sms.core.data.ScanResultEntity
import com.scamshield.sms.core.network.LocalResult
import com.scamshield.sms.core.network.LogMessage
import com.scamshield.sms.core.network.Reason
import com.scamshield.sms.core.network.ReportLogIn
import com.scamshield.sms.core.network.ScanFeatures
import com.scamshield.sms.core.network.ScanIn
import com.scamshield.sms.core.network.ScanOut
import kotlinx.coroutines.delay
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import retrofit2.HttpException
import java.io.IOException
import java.time.Instant
import java.util.concurrent.TimeUnit

/**
 * Scans one incoming SMS (context file §4.4):
 *  1. on-device rules → verdict immediately (works offline)
 *  2. server check (sender + links + reason codes; full text only if the user opted in)
 *  3. poll until deep link analysis finishes
 *  4. if the server asks for the SMS log (auto-report consent), upload ONLY this sender's messages
 */
class ScanWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    companion object {
        private const val KEY_ID = "message_id"
        private const val POLL_EVERY_MS = 3_000L
        private const val POLL_MAX = 15

        fun enqueue(context: Context, messageId: Long) {
            val req = OneTimeWorkRequestBuilder<ScanWorker>()
                .setInputData(workDataOf(KEY_ID to messageId))
                .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork("scan-$messageId", ExistingWorkPolicy.KEEP, req)
        }
    }

    private val c = ctx.container

    override suspend fun getForegroundInfo(): ForegroundInfo {
        val n = c.notifier.backgroundNotification()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ForegroundInfo(42, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            ForegroundInfo(42, n)
        }
    }

    override suspend fun doWork(): Result {
        val id = inputData.getLong(KEY_ID, -1)
        val msg = c.sms.message(id) ?: return Result.success()
        if (msg.type != Telephony.Sms.MESSAGE_TYPE_INBOX) return Result.success()
        val dao = c.db.scanDao()
        val json = c.api.json
        val reasonsSer = ListSerializer(Reason.serializer())
        val name = c.sms.contactName(msg.address)
        val inContacts = name != null

        // 1. local pass (only once; retries skip it)
        var row = dao.get(id)
        val localInitial = c.scanner.scan(msg.address, msg.body, inContacts)
        // Sender the user marked safe: no AI, no server, never flagged.
        if (c.db.trustedDao().isTrusted(localInitial.sender.norm)) {
            if (row == null) {
                dao.upsert(ScanResultEntity(
                    messageId = id, threadId = msg.threadId, sender = msg.address, status = "COMPLETE",
                    verdict = Verdict.SAFE.name, score = 0, reasonsJson = "[]", feedback = "not_scam",
                ))
            }
            return Result.success()
        }
        val local = com.scamshield.sms.core.security.DeepSeekScanner.scanWithDeepSeek(msg.address, msg.body, inContacts, localInitial)
        if (row == null) {
            val reasons = local.score.signals.map { Reason(it.code, it.text, it.points, it.detail) }
            row = ScanResultEntity(
                messageId = id, threadId = msg.threadId, sender = msg.address, status = "LOCAL",
                verdict = local.score.verdict.name, score = local.score.score,
                reasonsJson = json.encodeToString(reasonsSer, reasons),
                impersonatedBrand = local.impersonatedBrand,
            )
            dao.upsert(row)
            c.notifier.showVerdict(msg, name, row.verdict, reasons, null)
        }

        // 2. server
        val s = c.settings.snapshot()
        if (!s.consentServer || s.deviceToken == null) return Result.success()
        var out: ScanOut = try {
            var res = c.api.service.scan(ScanIn(
                messageId = id.toString(),
                sender = msg.address,
                receivedAt = Instant.ofEpochMilli(msg.date).toString(),
                simSlot = msg.subId.takeIf { it >= 0 },
                urls = local.urls,
                local = LocalResult(local.score.score, local.reasonCodes),
                features = ScanFeatures(inContacts = inContacts),
                text = if (s.shareText) msg.body else null,
            ))
            // 3. poll deep analysis
            var polls = 0
            while (res.status == "partial" && polls++ < POLL_MAX) {
                save(row, res, "PARTIAL")
                delay(POLL_EVERY_MS)
                res = c.api.service.getScan(res.scanId)
            }
            res
        } catch (e: IOException) {
            return Result.retry()
        } catch (e: HttpException) {
            return if (e.code() >= 500) Result.retry() else Result.success()
        }

        val previous = row.verdict
        // The server doesn't know the sender is a friend; trust the AI's SAFE for saved contacts.
        // For others, cap the server's SCAM at the AI's milder verdict when the text has no links.
        val ai = local.aiVerdict
        if (ai != null && ai != Verdict.SCAM && out.verdict == "SCAM" && (inContacts || local.urls.isEmpty())) {
            out = out.copy(verdict = ai.name, report = null)
        }
        row = save(row, out,if (out.status == "complete") "COMPLETE" else "PARTIAL")
        val reportLine = out.report?.let { r ->
            if (r.mode == "demo") "Report ${r.id} prepared (demo mode)" else "Reported automatically · ${r.id}"
        }
        if (row.verdict != previous || out.report != null) {
            c.notifier.showVerdict(msg, name, out.verdict, out.reasons, reportLine)
        }

        // 4. SMS log for the auto-report: only this sender's messages in this thread
        val rep = out.report
        if (rep != null && rep.needsLog) {
            val log = c.sms.messagesFromSender(msg.threadId, msg.address).takeLast(50).map {
                LogMessage(it.address, it.body, Instant.ofEpochMilli(it.date).toString(), it.subId.takeIf { sub -> sub >= 0 })
            }
            try {
                val ref = c.api.service.reportLog(ReportLogIn(out.scanId, log))
                dao.upsert(row.copy(reportStatus = ref.status, updatedAt = System.currentTimeMillis()))
            } catch (e: IOException) {
                return Result.retry()
            }
        }
        if (out.verdict == "SCAM" && s.auto1909) {
            runCatching { c.smsSender.send("1909", msg.body) }
        }
        return Result.success()
    }

    private suspend fun save(row: ScanResultEntity, out: ScanOut, status: String): ScanResultEntity {
        val json = c.api.json
        val updated = row.copy(
            status = status,
            verdict = out.verdict,
            score = out.score,
            reasonsJson = json.encodeToString(ListSerializer(Reason.serializer()), out.reasons),
            urlsJson = json.encodeToString(ListSerializer(com.scamshield.sms.core.network.UrlOut.serializer()), out.urls),
            serverScanId = out.scanId,
            impersonatedBrand = out.impersonatedBrand ?: row.impersonatedBrand,
            reportId = out.report?.id ?: row.reportId,
            reportStatus = out.report?.status ?: row.reportStatus,
            reportMode = out.report?.mode ?: row.reportMode,
            reportIntendedJson = out.report?.let { json.encodeToString(ListSerializer(JsonObject.serializer()), it.intended) }
                ?: row.reportIntendedJson,
            portalsJson = json.encodeToString(
                ListSerializer(com.scamshield.sms.core.network.Portal.serializer()), out.portals,
            ),
            updatedAt = System.currentTimeMillis(),
        )
        c.db.scanDao().upsert(updated)
        return updated
    }
}

/** Daily download of blocked senders + phishing domain hashes for offline checks. */
class BlocklistSyncWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    companion object {
        fun schedule(context: Context) {
            val req = PeriodicWorkRequestBuilder<BlocklistSyncWorker>(12, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork("blocklist-sync", ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun runNow(context: Context) {
            WorkManager.getInstance(context).enqueueUniqueWork(
                "blocklist-sync-now", ExistingWorkPolicy.REPLACE,
                OneTimeWorkRequestBuilder<BlocklistSyncWorker>().build(),
            )
        }
    }

    override suspend fun doWork(): Result {
        val c = applicationContext.container
        val s = c.settings.snapshot()
        if (s.deviceToken == null) return Result.success()
        return try {
            val out = c.api.service.blocklist(s.blocklistVersion)
            c.blocklist.replace(out.full, out.senders, out.domainHashes)
            c.settings.update { it.copy(blocklistVersion = out.version) }
            Result.success()
        } catch (e: IOException) {
            Result.retry()
        } catch (e: HttpException) {
            Result.retry()
        }
    }
}
