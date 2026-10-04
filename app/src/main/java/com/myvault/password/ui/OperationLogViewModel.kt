package com.myvault.password.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.myvault.password.AppContainer
import com.myvault.password.operationlog.OpKind
import com.myvault.password.operationlog.OperationLogEntry
import com.myvault.password.operationlog.renderLogEntry
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * 一条已经渲染好的日志。
 *
 * 渲染（把结构化事实拼成句子）发生在 ViewModel 里而不是界面里，
 * 好处有两个：
 *  1. 界面只做排版，日志「长什么样」只有一处定义，不会出现
 *     「某类操作写进了日志但界面上看不出含义」；
 *  2. 渲染逻辑是纯函数，可以在纯 JVM 上单测，不必启动 Android 运行时。
 */
data class OperationLogViewItem(
    val entry: OperationLogEntry,
    /** 操作名（如「删除条目」）对应的字符串资源。 */
    val titleRes: Int,
    /** 细节行（如「名称：支付宝」）。 */
    val detailLines: List<String>,
    /** 是否涉及重名 —— 界面据此用警示色显示。 */
    val hasDuplicateNames: Boolean,
) {
    val kind: OpKind get() = entry.kind
    val at: Long get() = entry.at
}

/** 操作日志界面状态。 */
data class OperationLogState(
    val loading: Boolean = true,
    val items: List<OperationLogViewItem> = emptyList(),
    val retentionDays: Int = 30,
)

/**
 * 操作日志 ViewModel。
 *
 * 只读：这个界面不提供任何「删除日志」「清空日志」的入口。
 * 一个可以被操作者随手抹掉的审计记录等于没有审计记录 ——
 * 想定期清理的用户可以用系统的「清除数据」，那是明确、可见的动作。
 */
class OperationLogViewModel(app: Application) : AndroidViewModel(app) {

    private val container = AppContainer.from(app)
    private val log = container.operationLog

    private val _state = MutableStateFlow(OperationLogState())
    val state: StateFlow<OperationLogState> = _state.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            val entries = log.recent()
            val items = entries.map { entry ->
                OperationLogViewItem(
                    entry = entry,
                    titleRes = entry.kind.titleRes,
                    detailLines = renderLogEntry(entry) { resId, args ->
                        getApplication<Application>().getString(resId, *args)
                    },
                    hasDuplicateNames = entry.otherNames.isNotEmpty() || entry.extraNameCount > 0,
                )
            }
            _state.update {
                it.copy(
                    loading = false,
                    items = items,
                    retentionDays = com.myvault.password.operationlog.VaultOperationLog.RETENTION_DAYS,
                )
            }
        }
    }
}
