package com.scamshield.sms.core.telephony

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.provider.BlockedNumberContract
import android.provider.ContactsContract
import android.provider.Telephony
import android.telephony.PhoneNumberUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import android.database.ContentObserver
import android.os.Handler
import android.os.Looper

data class SmsMessage(
    val id: Long,
    val threadId: Long,
    val address: String,
    val body: String,
    val date: Long,
    val type: Int,          // Telephony.Sms.MESSAGE_TYPE_*
    val read: Boolean,
    val status: Int,        // Telephony.Sms.STATUS_*
    val subId: Int,
) {
    val incoming get() = type == Telephony.Sms.MESSAGE_TYPE_INBOX
}

data class Conversation(
    val threadId: Long,
    val address: String,
    val displayName: String?,
    val snippet: String,
    val date: Long,
    val unread: Int,
)

/**
 * All reads/writes of the system SMS store. The app is the default SMS app, so it is
 * responsible for writing incoming and outgoing messages into the provider itself.
 * (SMS-only for phase 1; MMS parts live in Telephony.Mms and arrive in phase 3.)
 */
class SmsRepository(private val context: Context) {
    private val resolver = context.contentResolver
    private val repoScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val contactCache = ConcurrentHashMap<String, String>()
    private val NO_CONTACT = "\u0000"

    val conversationsFlow: StateFlow<List<Conversation>?> =
        changes()
            .map { conversations() }
            .flowOn(Dispatchers.IO)
            .stateIn(
                scope = repoScope,
                started = SharingStarted.Eagerly,
                initialValue = null
            )
    private val projection = arrayOf(
        Telephony.Sms._ID, Telephony.Sms.THREAD_ID, Telephony.Sms.ADDRESS, Telephony.Sms.BODY,
        Telephony.Sms.DATE, Telephony.Sms.TYPE, Telephony.Sms.READ, Telephony.Sms.STATUS,
        Telephony.Sms.SUBSCRIPTION_ID,
    )

    /** Emits Unit whenever anything in the SMS provider changes. */
    fun changes(): Flow<Unit> = callbackFlow {
        val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) {
                trySend(Unit)
            }
        }
        resolver.registerContentObserver(Telephony.Sms.CONTENT_URI, true, observer)
        // Thread deletes on some devices only notify the combined mms-sms URI.
        resolver.registerContentObserver(Telephony.MmsSms.CONTENT_URI, true, observer)
        trySend(Unit)
        awaitClose { resolver.unregisterContentObserver(observer) }
    }.conflate()

    fun observeConversations(): Flow<List<Conversation>> =
        changes().map { conversations() }.flowOn(Dispatchers.IO)

    fun observeThread(threadId: Long): Flow<List<SmsMessage>> =
        changes().map { messages(threadId) }.flowOn(Dispatchers.IO)

    fun conversations(limitRows: Int = 5000): List<Conversation> {
        val latest = LinkedHashMap<Long, SmsMessage>()
        val unread = HashMap<Long, Int>()
        resolver.query(Telephony.Sms.CONTENT_URI, projection, null, null, "${Telephony.Sms.DATE} DESC")?.use { c ->
            var n = 0
            while (c.moveToNext() && n++ < limitRows) {
                val m = c.toMessage()
                if (m.threadId !in latest) latest[m.threadId] = m
                if (!m.read && m.incoming) unread[m.threadId] = (unread[m.threadId] ?: 0) + 1
            }
        }
        val names = HashMap<String, String?>()
        return latest.values.map { m ->
            Conversation(
                threadId = m.threadId,
                address = m.address,
                displayName = names.getOrPut(m.address) { contactName(m.address) },
                snippet = m.body,
                date = m.date,
                unread = unread[m.threadId] ?: 0,
            )
        }
    }

    fun messages(threadId: Long): List<SmsMessage> {
        val out = mutableListOf<SmsMessage>()
        resolver.query(
            Telephony.Sms.CONTENT_URI, projection, "${Telephony.Sms.THREAD_ID} = ?",
            arrayOf(threadId.toString()), "${Telephony.Sms.DATE} ASC",
        )?.use { c -> while (c.moveToNext()) out += c.toMessage() }
        return out
    }

    fun message(id: Long): SmsMessage? =
        resolver.query(
            Telephony.Sms.CONTENT_URI, projection, "${Telephony.Sms._ID} = ?", arrayOf(id.toString()), null,
        )?.use { c -> if (c.moveToFirst()) c.toMessage() else null }

    /** Messages from the same sender in the same thread (the "SMS log" for a report — nothing else). */
    fun messagesFromSender(threadId: Long, address: String): List<SmsMessage> =
        messages(threadId).filter {
            it.incoming && (it.address == address || PhoneNumberUtils.compare(it.address, address))
        }

    fun threadIdFor(address: String): Long = Telephony.Threads.getOrCreateThreadId(context, address)

    suspend fun insertIncoming(address: String, body: String, sentAt: Long, subId: Int): Uri? =
        withContext(Dispatchers.IO) {
            val values = ContentValues().apply {
                put(Telephony.Sms.ADDRESS, address)
                put(Telephony.Sms.BODY, body)
                put(Telephony.Sms.DATE, System.currentTimeMillis())
                put(Telephony.Sms.DATE_SENT, sentAt)
                put(Telephony.Sms.READ, 0)
                put(Telephony.Sms.SEEN, 0)
                put(Telephony.Sms.TYPE, Telephony.Sms.MESSAGE_TYPE_INBOX)
                put(Telephony.Sms.SUBSCRIPTION_ID, subId)
                put(Telephony.Sms.THREAD_ID, threadIdFor(address))
            }
            resolver.insert(Telephony.Sms.Inbox.CONTENT_URI, values)
        }

    fun insertOutgoing(address: String, body: String, subId: Int): Uri? {
        val values = ContentValues().apply {
            put(Telephony.Sms.ADDRESS, address)
            put(Telephony.Sms.BODY, body)
            put(Telephony.Sms.DATE, System.currentTimeMillis())
            put(Telephony.Sms.READ, 1)
            put(Telephony.Sms.SEEN, 1)
            put(Telephony.Sms.TYPE, Telephony.Sms.MESSAGE_TYPE_OUTBOX)
            put(Telephony.Sms.STATUS, Telephony.Sms.STATUS_PENDING)
            put(Telephony.Sms.SUBSCRIPTION_ID, subId)
            put(Telephony.Sms.THREAD_ID, threadIdFor(address))
        }
        return resolver.insert(Telephony.Sms.Outbox.CONTENT_URI, values)
    }

    fun updateType(uri: Uri, type: Int, errorCode: Int? = null) {
        val v = ContentValues().apply {
            put(Telephony.Sms.TYPE, type)
            errorCode?.let { put(Telephony.Sms.ERROR_CODE, it) }
        }
        resolver.update(uri, v, null, null)
    }

    fun updateStatus(uri: Uri, status: Int) {
        resolver.update(uri, ContentValues().apply { put(Telephony.Sms.STATUS, status) }, null, null)
    }

    suspend fun markThreadRead(threadId: Long) = withContext(Dispatchers.IO) {
        val v = ContentValues().apply { put(Telephony.Sms.READ, 1); put(Telephony.Sms.SEEN, 1) }
        resolver.update(
            Telephony.Sms.CONTENT_URI, v, "${Telephony.Sms.THREAD_ID} = ? AND ${Telephony.Sms.READ} = 0",
            arrayOf(threadId.toString()),
        )
    }

    suspend fun deleteThread(threadId: Long) = withContext(Dispatchers.IO) {
        // Delete by thread_id per table: the mms-sms thread URI silently deletes nothing on some devices.
        val arg = arrayOf(threadId.toString())
        val sms = try {
            resolver.delete(Telephony.Sms.CONTENT_URI, "${Telephony.Sms.THREAD_ID} = ?", arg)
        } catch (e: Exception) {
            android.util.Log.e("SmsRepository", "deleteThread($threadId) failed", e); throw e
        }
        android.util.Log.d("SmsRepository", "deleteThread($threadId): sms rows=$sms")
        val mms = runCatching { resolver.delete(Telephony.Mms.CONTENT_URI, "${Telephony.Mms.THREAD_ID} = ?", arg) }.getOrDefault(0)
        // The provider may not notify observers for a bulk delete; make sure the lists refresh.
        resolver.notifyChange(Telephony.Sms.CONTENT_URI, null)
        sms + mms
    }

    suspend fun deleteMessage(id: Long) = withContext(Dispatchers.IO) {
        resolver.delete(Uri.withAppendedPath(Telephony.Sms.CONTENT_URI, id.toString()), null, null)
    }

    // ------------------------------------------------------------- contacts & blocking
    fun contactName(address: String): String? {
        if (address.isBlank() || address.any { it.isLetter() }) return null
        val cached = contactCache[address]
        if (cached != null) return if (cached == NO_CONTACT) null else cached
        val name = try {
            resolver.query(
                Uri.withAppendedPath(ContactsContract.PhoneLookup.CONTENT_FILTER_URI, Uri.encode(address)),
                arrayOf(ContactsContract.PhoneLookup.DISPLAY_NAME), null, null, null,
            )?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
        } catch (e: SecurityException) {
            null // READ_CONTACTS not granted
        } catch (e: IllegalArgumentException) {
            null // alphanumeric sender IDs can't be looked up
        }
        contactCache[address] = name ?: NO_CONTACT
        return name
    }

    fun isInContacts(address: String) = contactName(address) != null

    fun canBlock(): Boolean = BlockedNumberContract.canCurrentUserBlockNumbers(context)

    fun isBlocked(address: String): Boolean =
        try { BlockedNumberContract.isBlocked(context, address) } catch (e: SecurityException) { false }

    suspend fun block(address: String) = withContext(Dispatchers.IO) {
        val v = ContentValues().apply { put(BlockedNumberContract.BlockedNumbers.COLUMN_ORIGINAL_NUMBER, address) }
        resolver.insert(BlockedNumberContract.BlockedNumbers.CONTENT_URI, v)
    }

    suspend fun unblock(address: String) = withContext(Dispatchers.IO) {
        BlockedNumberContract.unblock(context, address)
    }

    private fun android.database.Cursor.toMessage() = SmsMessage(
        id = getLong(0),
        threadId = getLong(1),
        address = getString(2) ?: "",
        body = getString(3) ?: "",
        date = getLong(4),
        type = getInt(5),
        read = getInt(6) == 1,
        status = getInt(7),
        subId = getInt(8),
    )
}
