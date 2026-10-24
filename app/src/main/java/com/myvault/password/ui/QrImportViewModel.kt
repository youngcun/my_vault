package com.myvault.password.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.myvault.password.AppContainer
import com.myvault.password.domain.VaultEntry
import com.myvault.password.qr.CredentialQr
import com.myvault.password.qr.QrCredential
import com.myvault.password.qr.QrError
import com.myvault.password.qr.QrFormatException
import com.myvault.password.qr.QrPayload
import com.myvault.password.qr.SealedBlob
import com.myvault.password.qr.UnsupportedKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 扫码导入的状态。
 *
 * 刻意把「扫描到的原始文本」也留着：用户点「重新扫描」之前，界面需要知道
 * 当前处于哪一步（明文待确认 / 加密待输入口令 / 无法识别），而不是靠若干个
 * 可空字段的排列组合去猜。
 */
data class QrImportState(
    /** 相机是否应当继续扫描。一旦有结果就停下来，避免同一张码反复触发。 */
    val scanning: Boolean = true,
    /** 已解析出的明文凭据（口令加密的二维码在解开前这里是 null）。 */
    val credential: QrCredential? = null,
    /** 待输入口令才能解开的载荷。 */
    val sealed: SealedBlob? = null,
    /** 认得出但无法导入的二维码种类。 */
    val unsupported: UnsupportedKind? = null,
    val error: QrError? = null,
    /** 正在解密 / 写入数据库。 */
    val working: Boolean = false,
    /** 密码是否明文显示。默认遮盖：导入是在公开场合做的动作概率很高。 */
    val passwordVisible: Boolean = false,
    /** 库里已有同名条目时带出名字，提示用户「这可能是重复的」。 */
    val duplicateSite: String? = null,
    /** 写入密码库失败（通常是自动锁定到期、会话已销毁）。 */
    val saveFailed: Boolean = false,
    /** 导入成功后的条目名；非空即表示可以返回列表了。 */
    val importedTitle: String? = null,
) {
    /** 当前是否已经拿到一条可导入的凭据（用于决定「导入」按钮是否可用）。 */
    val ready: Boolean get() = credential != null && !working
}

/**
 * 扫码导入 ViewModel。
 *
 * 负责三件事，且每件都**不碰界面**：
 *  1. 把扫描结果按 [CredentialQr] 的规则解析成结构化状态；
 *  2. 需要口令时解密（Argon2id，耗时几百毫秒到数秒，必须在 IO 线程）；
 *  3. 写入密码库，并回读确认。
 */
class QrImportViewModel(app: Application) : AndroidViewModel(app) {

    private val container = AppContainer.from(app)
    private val repository = container.repository

    private val _state = MutableStateFlow(QrImportState())
    val state: StateFlow<QrImportState> = _state.asStateFlow()

    /**
     * 处理一条扫描到的文本。
     *
     * 重复扫描（相机每帧都会命中同一张码）由界面层先暂停相机保证，
     * 这里再做一次幂等保护：已经拿到结果时忽略新的文本。
     */
    fun onScanResult(raw: String) {
        if (_state.value.credential != null || _state.value.sealed != null) return
        val parsed = try {
            CredentialQr.parse(raw)
        } catch (e: QrFormatException) {
            _state.update {
                it.copy(scanning = false, error = e.error, credential = null, sealed = null, unsupported = null)
            }
            return
        }
        when (parsed) {
            is QrPayload.Plain -> onCredential(parsed.credential)
            is QrPayload.Sealed -> _state.update {
                it.copy(scanning = false, sealed = parsed.blob, error = null, unsupported = null)
            }
            is QrPayload.Unsupported -> _state.update {
                it.copy(scanning = false, unsupported = parsed.kind, error = null, credential = null, sealed = null)
            }
        }
    }

    /** 用户输入口令后解开加密载荷。口令错误与内容被篡改在这里是同一个结果。 */
    fun unlockSealed(passphrase: CharArray) {
        val blob = _state.value.sealed ?: return
        if (_state.value.working) return
        _state.update { it.copy(working = true) }
        viewModelScope.launch {
            val result = withContext(Dispatchers.Default) {
                runCatching { CredentialQr.open(blob, passphrase) }
            }
            // 口令用后立刻清零：它可能停在输入框的 CharArray 里被复用
            passphrase.fill('\u0000')
            result.fold(
                onSuccess = { credential ->
                    _state.update { it.copy(working = false, sealed = null, error = null) }
                    onCredential(credential)
                },
                onFailure = { e ->
                    val reason = (e as? QrFormatException)?.error ?: QrError.WRONG_PASSPHRASE
                    _state.update { it.copy(working = false, error = reason) }
                },
            )
        }
    }

    /** 重新扫描：清空一切解析结果，恢复相机。 */
    fun rescan() {
        _state.value = QrImportState()
    }

    fun togglePasswordVisible() =
        _state.update { it.copy(passwordVisible = !it.passwordVisible) }

    /**
     * 把当前凭据写入密码库。
     *
     * 使用**新的 UUID** 而不是二维码里的任何标识：二维码里本就不带 id
     * （见 [QrCredential] 的说明），因此每次导入都是一条新记录，
     * 重复扫码不会静默覆盖已有条目 —— 那正是「导入两次把密码改没了」的成因。
     */
    fun importCredential() {
        val credential = _state.value.credential ?: return
        if (_state.value.working) return
        _state.update { it.copy(working = true, error = null) }

        viewModelScope.launch {
            val entry = VaultEntry(
                site = credential.site.trim(),
                username = credential.username,
                password = credential.password,
                url = credential.url.trim(),
                notes = credential.notes,
                // 从二维码来的密码不是本机生成的：界面上的「由生成器产生」标记不能撒谎
                generated = false,
            )
            val result = runCatching { repository.saveEntry(entry) }
            result.fold(
                onSuccess = { saved ->
                    _state.update {
                        it.copy(
                            working = false,
                            importedTitle = saved.site.ifBlank { saved.username },
                        )
                    }
                },
                onFailure = {
                    // 写不进去通常只有一个原因：会话已锁定（自动锁定到期）。
                    _state.update { it.copy(working = false, saveFailed = true) }
                },
            )
        }
    }

    /** 消费一次性错误，避免旋转屏幕后重复弹出。 */
    fun consumeError() = _state.update { it.copy(error = null) }

    // ------------------------------------------------------------ 内部

    private fun onCredential(credential: QrCredential) {
        _state.update {
            it.copy(scanning = false, credential = credential, error = null, unsupported = null)
        }
        // 重名检测是**提示**而不是阻断：同一个站点有第二个账号完全合法，
        // 程序没有资格替用户判断哪个才是「对的」。
        viewModelScope.launch {
            val duplicate = runCatching {
                val site = credential.site.trim()
                if (site.isEmpty()) {
                    null
                } else {
                    repository.loadEntries()
                        .firstOrNull { it.site.trim().equals(site, ignoreCase = true) }
                        ?.site
                }
            }.getOrNull()
            if (duplicate != null) {
                _state.update { it.copy(duplicateSite = duplicate) }
            }
        }
    }
}
