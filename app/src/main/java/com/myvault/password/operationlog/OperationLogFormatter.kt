package com.myvault.password.operationlog

import com.myvault.password.R

/**
 * 把结构化日志渲染成给人看的文字。
 *
 * 为什么渲染放在这里而不是界面里：这是**唯一**一处决定「一条日志长什么样」
 * 的地方。界面只负责把它按行贴出来，因此「新增一种操作」时不会出现
 * 「日志写进去了但界面上看不出所以然」的情况 —— 那正是审计功能最容易失败的形态。
 *
 * 渲染结果只有两种来源：资源字符串 + 用户自己输入过的名称。
 * 任何凭据内容都不参与渲染 —— 写入侧由 [VaultOperationLog] 的方法签名保证，
 * 渲染侧由 [OpKind.hidesNames] 兜底。
 *
 * @param res 资源读取函数（界面传 `stringResource` 的等价实现，测试传纯函数）
 */
fun renderLogEntry(entry: OperationLogEntry, res: (Int, Array<out Any>) -> String): List<String> {
    // 兜底防线：与名称无关的操作不得把名称渲染出来。
    // 这条检查存在的意义是「将来」—— 如果哪天有人给改密码的日志带上了
    // 某个站点名，这里会立刻把它挡在界面之外，而不是让它安静地出现在
    // 每一个打开日志的人眼前。
    val safe = if (entry.kind.hidesNames) {
        entry.copy(site = null, oldSite = null, newSite = null)
    } else {
        entry
    }

    val lines = ArrayList<String>(3)
    val site = safe.site.orEmpty()
    when (safe.kind) {
        OpKind.ENTRY_DELETED,
        OpKind.ENTRY_DELETED_IN_DETAIL,
        -> lines += res(R.string.oplog_detail_site, arrayOf(site.ifBlank { unnamed(res) }))

        OpKind.MASTER_PASSWORD_CHANGED ->
            // 刻意只给出「数据没有被重新加密」这一条事实：它有实际价值
            // （用户据此知道改密码是瞬间完成的，且不会因为改密码而丢失任何条目）。
            lines += res(R.string.oplog_detail_password_note, emptyArray())

        OpKind.SITE_RENAMED -> {
            val old = safe.oldSite.orEmpty().ifBlank { unnamed(res) }
            val new = safe.newSite.orEmpty().ifBlank { unnamed(res) }
            lines += res(R.string.oplog_detail_renamed, arrayOf(old, new))
        }

        OpKind.BACKUP_EXPORTED -> {
            val count = safe.count ?: 0
            lines += res(R.string.oplog_detail_exported, arrayOf(count))
            safe.fileName?.takeIf { it.isNotBlank() }?.let {
                lines += res(R.string.oplog_detail_file, arrayOf(it))
            }
        }

        OpKind.BACKUP_RESTORED -> {
            val count = safe.count ?: 0
            val skipped = safe.skipped ?: 0
            lines += res(R.string.oplog_detail_imported, arrayOf(count, skipped))
            safe.fileName?.takeIf { it.isNotBlank() }?.let {
                lines += res(R.string.oplog_detail_file, arrayOf(it))
            }
            if (safe.otherNames.isNotEmpty()) {
                // 重名是这条日志里最需要被看见的信息，单独占一行并带上警告语义
                lines += res(
                    R.string.oplog_detail_duplicates,
                    arrayOf(safe.otherNames.joinToString("、")),
                )
            }
            if (safe.extraNameCount > 0) {
                lines += res(R.string.oplog_detail_duplicates_more, arrayOf(safe.extraNameCount))
            }
        }
    }
    return lines
}

/** 名称为空时的占位说明。 */
private fun unnamed(res: (Int, Array<out Any>) -> String): String =
    res(R.string.oplog_unnamed, emptyArray())
