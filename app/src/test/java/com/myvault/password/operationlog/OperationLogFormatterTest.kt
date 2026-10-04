package com.myvault.password.operationlog

import com.myvault.password.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 日志渲染测试。
 *
 * 这里钉住的是**信息完整性**：一条日志必须能让人只看界面就明白
 * 「谁、什么时候、做了什么、涉及哪个名称」。审计记录最典型的失败形态
 * 不是崩溃，而是「写了但看不出含义」—— 那样的日志等于没写。
 *
 * 渲染是纯函数（资源 id 由调用方解析），因此可以在纯 JVM 上跑，
 * 不需要启动 Android 运行时。
 */
class OperationLogFormatterTest {

    /**
     * 极简的资源替身：把资源 id 换成一个稳定的占位符 + 参数，
     * 这样断言就不依赖任何真实文案，改文案不会让测试变红，
     * 但「参数有没有传进去」仍然会被严格检查。
     */
    private val fakeRes: (Int, Array<out Any>) -> String = { id, args ->
        "res$id(" + args.joinToString(",") { it.toString() } + ")"
    }

    @Test
    fun `删除条目带上名称`() {
        val lines = renderLogEntry(
            OperationLogEntry(kind = OpKind.ENTRY_DELETED, at = 0, site = "支付宝"),
            fakeRes,
        )
        assertEquals(listOf("res${R.string.oplog_detail_site}(支付宝)"), lines)
    }

    @Test
    fun `名称为空时给出可读的占位而不是空白`() {
        val lines = renderLogEntry(
            OperationLogEntry(kind = OpKind.ENTRY_DELETED, at = 0, site = "  "),
            fakeRes,
        )
        assertEquals(listOf("res${R.string.oplog_detail_site}(res${R.string.oplog_unnamed}())"), lines)
    }

    @Test
    fun `改名同时给出旧名与新名`() {
        val lines = renderLogEntry(
            OperationLogEntry(
                kind = OpKind.SITE_RENAMED,
                at = 0,
                oldSite = "旧站点",
                newSite = "新站点",
            ),
            fakeRes,
        )
        assertEquals(listOf("res${R.string.oplog_detail_renamed}(旧站点,新站点)"), lines)
    }

    @Test
    fun `改密码不携带任何口令内容`() {
        val lines = renderLogEntry(
            OperationLogEntry(kind = OpKind.MASTER_PASSWORD_CHANGED, at = 0),
            fakeRes,
        )
        assertEquals(1, lines.size)
        assertTrue("改密码只应渲染说明性文字，不得有任何参数", lines[0].contains("()"))
    }

    /**
     * 与名称无关的操作**即使被塞了名称也不会渲染出来**。
     *
     * 这是渲染侧的兜底防线：改密码与备份操作本身不涉及某一个站点，
     * 万一将来有人往这两类日志里带了名称字段，界面必须把它挡住 ——
     * 日志是明文文件，名称一旦被渲染出来就等于多一处暴露面。
     */
    @Test
    fun `改密码与备份操作会丢弃意外的名称字段`() {
        val polluted = OperationLogEntry(
            kind = OpKind.MASTER_PASSWORD_CHANGED,
            at = 0,
            site = "不该出现的名称",
            oldSite = "不该出现的旧名",
            newSite = "不该出现的新名",
        )
        for (kind in listOf(OpKind.MASTER_PASSWORD_CHANGED, OpKind.BACKUP_EXPORTED, OpKind.BACKUP_RESTORED)) {
            val rendered = renderLogEntry(polluted.copy(kind = kind), fakeRes).joinToString("\n")
            assertTrue("$kind 不应渲染名称字段：$rendered", !rendered.contains("不该出现"))
        }

        // 但文件名必须保留：它是必要的审计信息（「这次用的是哪一份备份」）
        val withFile = renderLogEntry(
            polluted.copy(kind = OpKind.BACKUP_RESTORED, fileName = "b.myvault"),
            fakeRes,
        ).joinToString("\n")
        assertTrue("备份文件名必须保留", withFile.contains("b.myvault"))
    }

    @Test
    fun `导出记录带上条目数与文件名`() {
        val lines = renderLogEntry(
            OperationLogEntry(
                kind = OpKind.BACKUP_EXPORTED,
                at = 0,
                count = 42,
                fileName = "myvault-backup-20261002-130000.myvault",
            ),
            fakeRes,
        )
        assertEquals(2, lines.size)
        assertEquals("res${R.string.oplog_detail_exported}(42)", lines[0])
        assertEquals(
            "res${R.string.oplog_detail_file}(myvault-backup-20261002-130000.myvault)",
            lines[1],
        )
    }

    /**
     * 重名必须单独占一行被渲染出来 —— 这是本次需求里最关键的一条：
     * 「从备份恢复时，如果有重名，要在操作日志中标出重名的名字」。
     */
    @Test
    fun `恢复时把重名的名字逐个列出来`() {
        val lines = renderLogEntry(
            OperationLogEntry(
                kind = OpKind.BACKUP_RESTORED,
                at = 0,
                count = 10,
                skipped = 2,
                otherNames = listOf("支付宝", "GitHub", "内部重名"),
                fileName = "b.myvault",
            ),
            fakeRes,
        )
        assertEquals(3, lines.size)
        val duplicateLine = lines.first { it.startsWith("res${R.string.oplog_detail_duplicates}") }
        assertTrue("重名行应列出全部重名：$duplicateLine", duplicateLine.contains("支付宝"))
        assertTrue("重名行应列出全部重名：$duplicateLine", duplicateLine.contains("GitHub"))
        assertTrue("重名行应列出全部重名：$duplicateLine", duplicateLine.contains("内部重名"))
        assertEquals(
            "res${R.string.oplog_detail_duplicates}(支付宝、GitHub、内部重名)",
            duplicateLine,
        )
        // 条目数与跳过数、文件名同样不能丢
        val countLine = lines.first { it.startsWith("res${R.string.oplog_detail_imported}") }
        assertEquals("res${R.string.oplog_detail_imported}(10,2)", countLine)
        assertTrue(lines.any { it.contains("b.myvault") })
    }

    @Test
    fun `超过上限的重名用剩余数量说明`() {
        val lines = renderLogEntry(
            OperationLogEntry(
                kind = OpKind.BACKUP_RESTORED,
                at = 0,
                count = 30,
                skipped = 0,
                otherNames = listOf("A"),
                extraNameCount = 5,
            ),
            fakeRes,
        )
        assertTrue(lines.any { it.contains("A") })
        assertTrue(lines.any { it.contains("5") })
    }

    @Test
    fun `没有重名时不渲染重名行`() {
        val lines = renderLogEntry(
            OperationLogEntry(kind = OpKind.BACKUP_RESTORED, at = 0, count = 3, skipped = 0),
            fakeRes,
        )
        assertEquals(1, lines.size)
    }

    /**
     * 每种操作类型都必须能被渲染出至少一行。
     *
     * 这条测试是「新增操作类型却忘了写渲染分支」的防线：那种情况下
     * 日志会被写进文件却永远显示为空白，用户看到的就是「记录丢了」。
     * 参数全部给上，确保每个分支走的是「信息最全」的那条路径。
     */
    @Test
    fun `每种操作类型都能渲染出可读内容`() {
        val filled = OperationLogEntry(
            kind = OpKind.ENTRY_DELETED,
            at = 0,
            site = "站点",
            oldSite = "旧名",
            newSite = "新名",
            count = 5,
            skipped = 1,
            otherNames = listOf("重名"),
            fileName = "f.myvault",
        )
        for (kind in OpKind.entries) {
            val lines = renderLogEntry(filled.copy(kind = kind), fakeRes)
            assertTrue("$kind 没有任何渲染内容", lines.isNotEmpty())
            assertTrue("$kind 渲染出了空行", lines.all { it.isNotBlank() })
        }
    }
}
