package com.myvault.password.operationlog

import com.myvault.password.R
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * 重要操作的类型。
 *
 * 记录范围**刻意收窄**到「用户会想知道『这事是不是我干的』」的操作：
 * 删除条目、修改主密码、修改站点/应用名称、导出与导入备份。
 * 浏览、搜索、复制这类高频动作不进日志 —— 它们既无审计价值，
 * 又会把日志淹掉，让真正重要的几条看不见。
 *
 * [hidesNames] 标记的是**明细信息不属于该操作**的类型：改密码与备份
 * 都不涉及某一个站点名。它的实际作用是渲染时的兜底 —— 万一将来有人
 * 往这两类日志里塞了名称字段，界面也不会把它显示出来。
 * 注意它不覆盖 [OperationLogEntry.fileName]：备份文件名是用户主动选择的
 * 文件标识，属于必要的审计信息（「这次恢复到底用的是哪一份备份」）。
 *
 * @param titleRes 人类可读的操作名。存在这里而不是持久化到日志里，
 *   是为了让日志文件保持语言中立：换语言后历史记录会用新语言重新渲染，
 *   而不是留下中英混杂的旧字符串。
 */
enum class OpKind(
    val titleRes: Int,
    val hidesNames: Boolean = false,
) {
    /** 在列表中删除条目。 */
    @SerialName("entry_deleted")
    ENTRY_DELETED(R.string.oplog_kind_entry_deleted),

    /** 在条目详情页删除条目。 */
    @SerialName("entry_deleted_in_detail")
    ENTRY_DELETED_IN_DETAIL(R.string.oplog_kind_entry_deleted_detail),

    /** 修改主密码（只记事实，不记任何口令内容）。 */
    @SerialName("master_password_changed")
    MASTER_PASSWORD_CHANGED(R.string.oplog_kind_password_changed, hidesNames = true),

    /** 修改站点 / 应用名称。 */
    @SerialName("site_renamed")
    SITE_RENAMED(R.string.oplog_kind_site_renamed),

    /** 导出加密备份。 */
    @SerialName("backup_exported")
    BACKUP_EXPORTED(R.string.oplog_kind_exported, hidesNames = true),

    /** 从备份恢复。 */
    @SerialName("backup_restored")
    BACKUP_RESTORED(R.string.oplog_kind_imported, hidesNames = true),
}

/**
 * 一条操作日志。
 *
 * 设计上刻意**只存结构化事实**：动作类型、时间、涉及的名称、条目数。
 * 界面上看到的整句话（例如「已删除条目『支付宝』」）是渲染时才拼出来的，
 * 因此日志文件本身既不含凭据，也不含任何一种自然语言的成品句子 ——
 * 前者是安全要求，后者是为了让中英文随时可切换。
 */
@Serializable
data class OperationLogEntry(
    @SerialName("kind") val kind: OpKind,
    @SerialName("at") val at: Long,

    /** 本次操作涉及的主要名称（站点 / 应用名称）。 */
    @SerialName("site") val site: String? = null,

    /** 改名前的旧名称。 */
    @SerialName("old_site") val oldSite: String? = null,

    /** 改名后的新名称。 */
    @SerialName("new_site") val newSite: String? = null,

    /** 导入/导出的条目数。 */
    @SerialName("count") val count: Int? = null,

    /** 同次操作中被跳过（重复）的条目数。 */
    @SerialName("skipped") val skipped: Int? = null,

    /** 恢复时与库内已有条目重名的名称列表（去重，最多 [MAX_LOGGED_NAMES] 个）。 */
    @SerialName("dup_names") val otherNames: List<String> = emptyList(),

    /** 除 [otherNames] 外还重名的条数（超出上限时被省略的那部分）。 */
    @SerialName("dup_more") val extraNameCount: Int = 0,

    /** 备份文件名。 */
    @SerialName("file") val fileName: String? = null,
) {
    companion object {
        /**
         * 单条日志里最多记多少个重名。
         *
         * 恢复一份大备份时可能有上百个重名，全写进一条日志会把界面撑爆，
         * 也会让日志文件失去可读性。超出的部分用「另有 N 个」表示 ——
         * 宁可少列几个名字，也不能因为名字太多而让规则失效。
         */
        const val MAX_LOGGED_NAMES = 20
    }
}

/** 日志时间的展示格式：短、稳定、与本机时区一致。 */
private val TIME_FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern("MM-dd HH:mm")

/**
 * 把时间戳格式化成列表里显示的短时间。
 *
 * 刻意不带年份：日志只保留 30 天，年份在正文里出现只会占地方。
 * 需要精确时间时可以看完整日志（自证报告用的是另一种格式）。
 */
fun formatLogTime(millis: Long): String =
    TIME_FORMATTER.format(Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()))

/** 日志按天分组的日期标题，例如「2026-10-02」。 */
fun formatLogDate(millis: Long): String =
    DateTimeFormatter.ofPattern("yyyy-MM-dd", Locale.US)
        .format(Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()))

/** 同一天内的两条日志是否应归入同一组。 */
fun sameLogDay(a: Long, b: Long): Boolean =
    formatLogDate(a) == formatLogDate(b)
