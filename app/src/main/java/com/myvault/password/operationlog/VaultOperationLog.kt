package com.myvault.password.operationlog

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/** 单条日志在磁盘上的形态：版本号 + 全部条目。 */
@Serializable
private data class OperationLogFile(
    @SerialName("v") val version: Int = CURRENT_FORMAT_VERSION,
    @SerialName("entries") val entries: List<OperationLogEntry> = emptyList(),
) {
    companion object {
        const val CURRENT_FORMAT_VERSION = 1
    }
}

/**
 * 一次「从备份恢复」的结果。
 *
 * 刻意区分「按 ID 重复而跳过」与「名称重名」：
 *  - 前者是导入策略决定的（用户可以自己选是否覆盖），属于正常行为；
 *  - 后者是**只有人才能判断的问题** —— 同一个站点出现两条记录，
 *    到底是「同一账号的第二个密码」还是「不小心导入了两遍」，
 *    程序无法判断，因此必须把它明确报出来并记入日志。
 *
 * @param imported 实际写入的条目数
 * @param skipped  因 ID 已存在且未开启覆盖而跳过的条目数
 * @param duplicateSiteNames 与库内已有条目重名（或备份内部彼此重名）的名称，
 *   去重且保持首次出现的顺序
 */
data class RestoreReport(
    val imported: Int,
    val skipped: Int,
    val duplicateSiteNames: List<String> = emptyList(),
) {
    /** 是否存在重名（界面据此决定要不要提示）。 */
    val hasDuplicates: Boolean get() = duplicateSiteNames.isNotEmpty()
}

/**
 * 操作日志：记录最近 30 天的重要操作。
 *
 * 三个必须守住的性质
 * ----------------
 *  1. **绝不写入凭据**。日志是明文文件（位于应用私有目录，受设备文件级加密保护），
 *     因此写入的只有操作类型、时间与名称。密码、用户名、备份口令一律不进日志 ——
 *     否则日志文件本身就成了比数据库更容易读的泄露源。
 *  2. **有界**。只保留 [RETENTION_DAYS] 天、最多 [MAX_ENTRIES] 条。
 *     日志必须自动收敛：一个只增不减的日志文件迟早会变成另一个需要维护的问题。
 *  3. **写入不破坏已有记录**。采用「写临时文件 → 原子替换」：
 *     进程在写到一半时被杀掉，宁可丢最后一条，也不能让整个日志文件变成半截 JSON
 *     而再也读不出来。
 *
 * 为什么不放进 Room 数据库：数据库有严格 schema 与显式 Migration 的约束（见
 * [com.myvault.password.data.VaultDatabase]），而日志是纯粹的旁路数据 ——
 * 它的格式变化不应该迫使整个密码库写迁移，也不该和「用户的密码」共用同一条
 * 崩溃恢复路径。因此它单独用一个 JSON 文件。
 *
 * 日志**不会被清空**，即使库被锁定或条目被全部删除：审计记录的价值恰恰在于
 * 「事后还能看到当时发生了什么」。
 */
class VaultOperationLog(
    private val file: File,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    /** 串行化所有读-改-写，避免并发记录时互相覆盖。 */
    private val mutex = Mutex()

    /**
     * 读取最近 30 天的日志，最新的在前。
     *
     * 为什么在读取时也做一次时间裁剪：应用可能连续几天没打开，
     * 磁盘上就留着超出 30 天的旧记录。界面上绝不能让它们出现 ——
     * 「近 30 天」必须由读取端保证，而不是依赖写入端恰好跑过一次清理。
     */
    suspend fun recent(now: Long = clock()): List<OperationLogEntry> = withContext(Dispatchers.IO) {
        val cutoff = now - RETENTION_MILLIS
        readFile()
            .filter { it.at in cutoff..now }
            .sortedByDescending { it.at }
            .take(MAX_ENTRIES)
    }

    // ------------------------------------------------------------ 记录入口

    /** 删除条目。 */
    suspend fun logEntryDeleted(site: String?, inDetailScreen: Boolean) = append(
        OperationLogEntry(
            kind = if (inDetailScreen) OpKind.ENTRY_DELETED_IN_DETAIL else OpKind.ENTRY_DELETED,
            at = clock(),
            site = site?.takeIf { it.isNotBlank() },
        ),
    )

    /** 修改主密码。**不接收任何口令参数** —— 从签名上就杜绝把口令写进日志。 */
    suspend fun logMasterPasswordChanged() = append(
        OperationLogEntry(kind = OpKind.MASTER_PASSWORD_CHANGED, at = clock()),
    )

    /**
     * 修改站点 / 应用名称。
     *
     * @param oldSite 改名前的名称；新建条目时为 null（不算改名，不记录）
     * @param newSite 改名后的名称
     */
    suspend fun logSiteRenamed(oldSite: String?, newSite: String) = append(
        OperationLogEntry(
            kind = OpKind.SITE_RENAMED,
            at = clock(),
            site = newSite,
            oldSite = oldSite,
            newSite = newSite,
        ),
    )

    /** 导出备份。@param fileName 实际落盘的文件名（回读系统得到，不是我们建议的名字）。 */
    suspend fun logBackupExported(entryCount: Int, fileName: String?) = append(
        OperationLogEntry(
            kind = OpKind.BACKUP_EXPORTED,
            at = clock(),
            count = entryCount,
            fileName = fileName,
        ),
    )

    /**
     * 从备份恢复。
     *
     * @param report 恢复结果，其中 [RestoreReport.duplicateSiteNames] 是本次恢复
     *   遇到的**重名**（与库内已有条目同名，或备份文件内部彼此同名）。
     *   这些名字会原样写进日志：用户需要在事后能看出「这次恢复把哪些名字弄重复了」。
     */
    suspend fun logBackupRestored(fileName: String?, report: RestoreReport) = append(
        OperationLogEntry(
            kind = OpKind.BACKUP_RESTORED,
            at = clock(),
            count = report.imported,
            skipped = report.skipped,
            otherNames = report.duplicateSiteNames.take(OperationLogEntry.MAX_LOGGED_NAMES),
            extraNameCount = (report.duplicateSiteNames.size - OperationLogEntry.MAX_LOGGED_NAMES)
                .coerceAtLeast(0),
            fileName = fileName,
        ),
    )

    // ------------------------------------------------------------ 内部实现

    private suspend fun append(entry: OperationLogEntry) {
        mutex.withLock {
            withContext(Dispatchers.IO) {
                val now = entry.at
                val cutoff = now - RETENTION_MILLIS
                val kept = readFile()
                    .filter { it.at in cutoff..now }
                    .sortedBy { it.at }                       // 旧 → 新，便于按上限截断
                    .takeLast(MAX_ENTRIES - 1)                // 给新记录留一个位置
                writeFile(kept + entry)
            }
        }
    }

    /**
     * 读取日志文件。
     *
     * 解析失败时返回空列表而不是抛异常：日志是旁路数据，
     * 它坏掉不该让任何主流程失败（记日志这件事永远不能拖累被记录的操作）。
     */
    private fun readFile(): List<OperationLogEntry> {
        if (!file.isFile) return emptyList()
        return try {
            val text = file.readText(Charsets.UTF_8)
            if (text.isBlank()) return emptyList()
            json.decodeFromString(OperationLogFile.serializer(), text).entries
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** 写临时文件后原子替换，避免写到一半留下半截 JSON。 */
    private fun writeFile(entries: List<OperationLogEntry>) {
        val text = json.encodeToString(
            OperationLogFile.serializer(),
            OperationLogFile(entries = entries),
        )
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        try {
            tmp.writeText(text, Charsets.UTF_8)
            if (!tmp.renameTo(file)) {
                // 某些文件系统上 rename 到已存在的目标会失败，退化为先删后改名
                file.delete()
                if (!tmp.renameTo(file)) {
                    // 最后兜底：直接覆盖写入。此时若失败，日志会丢，
                    // 但绝不能把异常抛给调用方 —— 记日志失败不是业务失败。
                    file.writeText(text, Charsets.UTF_8)
                }
            }
        } catch (e: Exception) {
            runCatching { tmp.delete() }
        }
    }

    companion object {
        /** 保留窗口：30 天。 */
        const val RETENTION_DAYS = 30

        /** 日志条数上限。防止「某天疯狂删除条目」把文件撑到不可控。 */
        const val MAX_ENTRIES = 2000

        const val RETENTION_MILLIS = RETENTION_DAYS * 24L * 60L * 60L * 1000L

        /** 日志文件名（位于应用私有目录）。 */
        const val FILE_NAME = "operation_log.json"
    }
}
