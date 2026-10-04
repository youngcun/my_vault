package com.myvault.password.operationlog

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.time.LocalDate
import java.time.ZoneId

/**
 * 操作日志测试。
 *
 * 重点覆盖三类风险：
 *  1. **留存边界**：日志必须只保留最近 30 天，且这个约束由**读取端**保证
 *     （应用可能几天没打开，磁盘上就会留下超期记录）；
 *  2. **不因日志而失败**：日志是旁路数据，文件损坏/写不进去都不该抛异常
 *     影响被记录的主操作；
 *  3. **有界**：条数上限必须真的生效，否则「疯狂删除条目」会把文件撑爆。
 */
class VaultOperationLogTest {

    @get:Rule
    val temp = TemporaryFolder()

    private fun logFile(): File = File(temp.root, VaultOperationLog.FILE_NAME)

    private val baseNow = 1_760_000_000_000L

    // ------------------------------------------------------------ 基本读写

    @Test
    fun `记录后可按时间倒序读回`() = runBlocking {
        var now = baseNow
        val log = VaultOperationLog(logFile(), clock = { now })

        log.logEntryDeleted("支付宝", inDetailScreen = false)
        now += 60_000
        log.logMasterPasswordChanged()
        now += 60_000
        log.logSiteRenamed(oldSite = "旧名", newSite = "新名")

        val entries = log.recent()
        assertEquals(3, entries.size)
        // 最新的在前
        assertEquals(OpKind.SITE_RENAMED, entries[0].kind)
        assertEquals("旧名", entries[0].oldSite)
        assertEquals("新名", entries[0].newSite)
        assertEquals(OpKind.MASTER_PASSWORD_CHANGED, entries[1].kind)
        assertEquals(OpKind.ENTRY_DELETED, entries[2].kind)
        assertEquals("支付宝", entries[2].site)
    }

    @Test
    fun `日志是持久的 新实例能读到同一份记录`() = runBlocking {
        val now = baseNow
        VaultOperationLog(logFile(), clock = { now }).logEntryDeleted("站点", inDetailScreen = true)

        // 模拟进程重启：换一个实例、同一个文件
        val entries = VaultOperationLog(logFile(), clock = { now }).recent()
        assertEquals(1, entries.size)
        assertEquals(OpKind.ENTRY_DELETED_IN_DETAIL, entries[0].kind)
        assertEquals("站点", entries[0].site)
    }

    /**
     * 日志文件的**字段白名单**。
     *
     * 这是这类测试唯一真正有效的形式：断言「文件里没有密码」是查不出来的
     * （密文与明文都可能凑巧不含某几个字符），但断言「日志里只有这几个字段」
     * 能挡住真正的风险 —— 将来有人往 [OperationLogEntry] 上加一个
     * `password` 或 `notes` 字段时，这条测试会立刻失败。
     */
    @Test
    fun `日志文件只包含白名单字段 不会记入凭据`() = runBlocking {
        val allowed = setOf("v", "entries", "kind", "at", "site", "old_site", "new_site", "count", "skipped", "dup_names", "dup_more", "file")
        val log = VaultOperationLog(logFile(), clock = { baseNow })
        log.logMasterPasswordChanged()
        log.logEntryDeleted("支付宝", inDetailScreen = false)
        log.logBackupExported(entryCount = 7, fileName = "myvault-backup-20261002-130000.myvault")
        log.logBackupRestored("b.myvault", RestoreReport(2, 1, listOf("GitHub")))

        val text = logFile().readText(Charsets.UTF_8)
        val keys = Regex("\"([a-z_]+)\"\\s*:").findAll(text).map { it.groupValues[1] }.toSet()
        assertEquals("日志里出现了白名单之外的字段，可能是凭据被写进了审计记录", allowed, keys)
        assertTrue("备份文件名应被记录（它是审计信息，不是凭据）", text.contains("myvault-backup"))
        assertTrue(text.contains("\"count\": 7"))
    }

    // ------------------------------------------------------------ 留存窗口

    @Test
    fun `超过 30 天的记录不再出现在读取结果里`() = runBlocking {
        var now = baseNow
        val log = VaultOperationLog(logFile(), clock = { now })
        log.logEntryDeleted("三十天前的删除", inDetailScreen = false)

        // 时间推进到 31 天之后
        now += 31L * 24 * 60 * 60 * 1000
        log.logEntryDeleted("今天的删除", inDetailScreen = false)

        val entries = log.recent()
        assertEquals("只应留下 30 天内的那一条", 1, entries.size)
        assertEquals("今天的删除", entries[0].site)

        // 磁盘上也不该继续堆积超期记录：读取端裁剪必须落到写入端
        val onDisk = VaultOperationLog(logFile(), clock = { now }).recent()
        assertEquals(1, onDisk.size)
    }

    @Test
    fun `第 30 天边界上的记录仍在窗口内`() = runBlocking {
        var now = baseNow
        val log = VaultOperationLog(logFile(), clock = { now })
        log.logEntryDeleted("边界内", inDetailScreen = false)

        // 恰好 30 天：窗口是闭区间 [now-30d, now]，应仍然可见
        now += VaultOperationLog.RETENTION_MILLIS
        assertEquals(1, log.recent().size)

        // 再晚 1 毫秒即超出窗口
        now += 1
        assertEquals(0, log.recent().size)
    }

    @Test
    fun `条数上限生效 只保留最新的若干条`() = runBlocking {
        var now = baseNow
        val log = VaultOperationLog(logFile(), clock = { now })
        // 写入超过上限的条数：全部在同一时间窗口内，因此只能靠条数上限收敛
        repeat(VaultOperationLog.MAX_ENTRIES + 5) { i ->
            now += 1000
            log.logEntryDeleted("站点-$i", inDetailScreen = false)
        }

        val entries = log.recent()
        assertEquals(VaultOperationLog.MAX_ENTRIES, entries.size)
        // 最新的一条必须在，最旧的几条必须已经被挤掉
        assertEquals("站点-${VaultOperationLog.MAX_ENTRIES + 4}", entries.first().site)
        assertTrue(
            "超出上限的旧记录应被丢弃",
            entries.none { it.site == "站点-0" },
        )
    }

    // ------------------------------------------------------------ 抗损坏

    @Test
    fun `日志文件损坏时读取返回空列表而不是抛异常`() = runBlocking {
        val file = logFile()
        file.parentFile?.mkdirs()
        file.writeText("{ 这不是合法 JSON", Charsets.UTF_8)

        val log = VaultOperationLog(file, clock = { baseNow })
        assertEquals(0, log.recent().size)

        // 损坏之后仍然可以继续记录：日志坏掉不能变成「永久性故障」
        log.logMasterPasswordChanged()
        assertEquals(1, log.recent().size)
    }

    @Test
    fun `未知字段的旧文件不会导致解析失败`() = runBlocking {
        // 模拟「更高版本写入的日志被回退版本读到」：多出来的字段应被忽略，
        // 而不是让整个日志变成不可读
        val file = logFile()
        file.parentFile?.mkdirs()
        file.writeText(
            """{"v":1,"future_field":"x","entries":[{"kind":"master_password_changed","at":$baseNow,"unknown":1}]}""",
            Charsets.UTF_8,
        )
        val entries = VaultOperationLog(file, clock = { baseNow }).recent()
        assertEquals(1, entries.size)
        assertEquals(OpKind.MASTER_PASSWORD_CHANGED, entries[0].kind)
    }

    @Test
    fun `恢复日志会带上重名与文件信息`() = runBlocking {
        val log = VaultOperationLog(logFile(), clock = { baseNow })
        log.logBackupRestored(
            fileName = "myvault-backup-20261002-130000.myvault",
            report = RestoreReport(
                imported = 12,
                skipped = 3,
                duplicateSiteNames = listOf("支付宝", "GitHub"),
            ),
        )

        val entry = log.recent().single()
        assertEquals(OpKind.BACKUP_RESTORED, entry.kind)
        assertEquals(12, entry.count)
        assertEquals(3, entry.skipped)
        assertEquals(listOf("支付宝", "GitHub"), entry.otherNames)
        assertEquals("myvault-backup-20261002-130000.myvault", entry.fileName)
    }

    @Test
    fun `重名数量超过上限时只记前若干个并给出剩余数量`() = runBlocking {
        val log = VaultOperationLog(logFile(), clock = { baseNow })
        val many = (1..30).map { "重名站点-$it" }
        log.logBackupRestored(fileName = null, report = RestoreReport(30, 0, many))

        val entry = log.recent().single()
        assertEquals(OperationLogEntry.MAX_LOGGED_NAMES, entry.otherNames.size)
        assertEquals(30 - OperationLogEntry.MAX_LOGGED_NAMES, entry.extraNameCount)
    }

    // ------------------------------------------------------------ 时间展示

    @Test
    fun `日期与时间格式可被人类直接读懂`() {
        val millis = LocalDate.of(2026, 10, 2).atTime(13, 5)
            .atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()
        assertEquals("2026-10-02", formatLogDate(millis))
        assertEquals("10-02 13:05", formatLogTime(millis))
        assertTrue(sameLogDay(millis, millis + 60_000))
        assertFalse(sameLogDay(millis, millis + 24L * 60 * 60 * 1000))
    }
}
