package com.myvault.password.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.myvault.password.AppContainer
import com.myvault.password.R
import com.myvault.password.audit.SecurityAudit
import com.myvault.password.data.IntegrityReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** 安全自证界面状态。 */
data class AuditState(
    val loading: Boolean = true,
    val report: SecurityAudit.Report? = null,
    val integrity: IntegrityReport? = null,
    val verifying: Boolean = false,
    val kdfDescription: String = "",
    /**
     * 密码套件的展示文案。
     *
     * 它是**技术常量**（算法名 + 标签长度），不是可翻译文案，
     * 因此刻意保持语言中立 —— 换成「认证标签」之类的译法反而会让
     * 第三方对照源码时更难辨认。
     */
    val cipherDescription: String = "AES-256-GCM (128-bit auth tag)",
    val reportText: String = "",
)

/**
 * 安全自证 ViewModel。
 *
 * 这个界面不提供任何「修改」能力 —— 它只是一面镜子：把编译好的 APK
 * 和运行中的进程的真实状态展示出来。用户据此可以自己判断，
 * 而不必相信应用商店描述或开发者的话。
 */
class AuditViewModel(app: Application) : AndroidViewModel(app) {

    private val container = AppContainer.from(app)
    private val audit = SecurityAudit(app)
    private val repository = container.repository

    private val _state = MutableStateFlow(AuditState())
    val state: StateFlow<AuditState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            val report = withContext(Dispatchers.IO) { audit.collect() }
            val envelope = repository.currentEnvelope
            val kdf = envelope?.describeKdf() ?: app.getString(R.string.audit_kdf_not_created)
            _state.update {
                it.copy(
                    loading = false,
                    report = report,
                    kdfDescription = kdf,
                    reportText = audit.renderText(report, kdf, it.cipherDescription),
                )
            }
        }
    }

    /** 主动重跑完整性校验。这是「可自证」的核心动作。 */
    fun verifyIntegrity() {
        viewModelScope.launch {
            _state.update { it.copy(verifying = true) }
            val result = try {
                repository.verifyIntegrity()
            } catch (e: Exception) {
                null
            }
            _state.update { it.copy(verifying = false, integrity = result) }
        }
    }

    /** 重新生成纯文本报告（用于复制到剪贴板）。 */
    fun rebuildReportText(): String {
        val s = _state.value
        val report = s.report ?: return ""
        return audit.renderText(report, s.kdfDescription, s.cipherDescription)
    }
}
