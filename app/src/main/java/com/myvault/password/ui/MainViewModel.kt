package com.myvault.password.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.myvault.password.AppContainer
import com.myvault.password.core.PasswordEntropy
import com.myvault.password.core.PasswordPolicy
import com.myvault.password.core.WrongSecretException
import com.myvault.password.data.VaultSession
import com.myvault.password.domain.VaultEntry
import com.myvault.password.util.ClipboardHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** 顶层界面状态。 */
sealed interface LockState {
    /** 正在判断「是否已创建密码库」。 */
    data object Loading : LockState

    /** 首次使用，需要设置主密码。 */
    data object NeedsSetup : LockState

    /** 已创建但未解锁。 */
    data object Locked : LockState

    /** 已解锁。 */
    data class Unlocked(val keyId: String) : LockState
}

/** 主界面状态。 */
data class MainUiState(
    val lockState: LockState = LockState.Loading,
    val entries: List<VaultEntry> = emptyList(),
    val query: String = "",
    val busy: Boolean = false,
    /** 一次性提示消息（Snackbar），消费后清空。 */
    val message: String? = null,
    val errorMessage: String? = null,
    /** 刚刚复制到剪贴板的条目 ID，用于界面反馈。 */
    val copiedEntryId: String? = null,
    val biometricAvailable: Boolean = false,
    /**
     * 无法解密的条目 ID。
     *
     * 它们不会出现在 [entries] 里（一条坏数据不该让整库打不开），
     * 但界面必须把它们显示出来 —— 否则「保存成功却读不回来」
     * 会表现得像什么都没发生。
     */
    val brokenEntryIds: List<String> = emptyList(),
) {
    val filteredEntries: List<VaultEntry>
        get() = if (query.isBlank()) entries else entries.filter { it.matches(query) }
}

/**
 * 主 ViewModel：解锁会话、条目列表、自动锁定、剪贴板。
 *
 * 自动锁定策略
 * ----------
 * 使用「前台计时器」而不是单纯的 Lifecycle 观察：仅靠 `onStop` 判定
 * 「用户离开了」在多窗口 / 分屏 / 快速切换等场景下会误判，导致要么
 * 该锁没锁，要么用户刚切出去就被锁死。这里的做法是：
 *  - 应用进入后台时记录时刻；
 *  - 回到前台时按设置的时长判断是否需要重新锁定；
 *  - 「立即」选项（0）则在后台瞬间即锁。
 */
class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val container = AppContainer.from(app)
    private val repository = container.repository
    private val settings = container.settings
    private val generator = container.passwordGenerator

    /**
     * 自动锁定的会话状态。
     *
     * 它与 [com.myvault.password.MainActivity] **共用同一个实例**（都取自容器）：
     * SAF 选择器、备份读写由 Activity 发起，它们必须能申请「暂停自动锁定」，
     * 而不能靠一条组合期注册的回调桥传进来 —— 那条桥自己出过缺陷
     * （第一次导出后引用被置空，导致第二次导出在选择文件时被锁定）。
     */
    private val autoLockSession = container.autoLockSession

    private val _state = MutableStateFlow(MainUiState())
    val state: StateFlow<MainUiState> = _state.asStateFlow()

    /** 条目订阅任务。 */
    private var collectJob: Job? = null

    init {
        viewModelScope.launch {
            repository.refreshSessionState()
            val initialized = repository.isInitialized()
            _state.update {
                it.copy(lockState = if (initialized) LockState.Locked else LockState.NeedsSetup)
            }
        }
        viewModelScope.launch {
            _state.update { it.copy(biometricAvailable = canUseBiometric()) }
        }
    }

    private fun canUseBiometric(): Boolean {
        val app = getApplication<Application>()
        val pm = app.packageManager
        return pm.hasSystemFeature(android.content.pm.PackageManager.FEATURE_FINGERPRINT)
    }

    // ------------------------------------------------------------ 会话

    /**
     * 指纹硬件 + 已注册生物识别 是否可用于**加密绑定**（界面据此决定是否显示指纹按钮）。
     *
     * 注意不能用 `canAuthenticate(STRONG or WEAK)` 来判断：那个组合在只有
     * Class 2（弱）生物识别的设备上也会返回成功，但**加密绑定必然失败**
     * （`Crypto-based authentication is not supported for Class 2 (Weak) biometrics`）。
     * 因此必须走 [com.myvault.password.core.BiometricCapability]，
     * 它只认「能真正保护密钥」的认证方式。
     */
    fun biometricReady(): Boolean =
        com.myvault.password.core.BiometricCapability.resolve(getApplication())
            .supportsCryptoObject

    /** 是否已启用指纹解锁（依据密钥信封，而不是设置项）。 */
    suspend fun biometricEnrolled(): Boolean {
        val initialized = repository.isInitialized()
        if (!initialized) return false
        return repository.biometricAliasSuffix() != null
    }

    fun setupVault(password: CharArray) {
        viewModelScope.launch {
            _state.update { it.copy(busy = true, errorMessage = null) }
            try {
                repository.createVault(password)
                onUnlocked()
            } catch (e: Exception) {
                _state.update {
                    it.copy(
                        busy = false,
                        errorMessage = e.message
                            ?: getApplication<Application>().getString(
                                com.myvault.password.R.string.error_create_failed,
                            ),
                    )
                }
            } finally {
                com.myvault.password.core.CryptoPrimitives.destroy(password)
            }
        }
    }

    fun unlock(password: CharArray) {
        viewModelScope.launch {
            _state.update { it.copy(busy = true, errorMessage = null) }
            try {
                repository.unlockWithPassword(password)
                onUnlocked()
            } catch (e: WrongSecretException) {
                _state.update {
                    it.copy(busy = false, errorMessage = getApplication<Application>().getString(
                        com.myvault.password.R.string.unlock_wrong_password,
                    ))
                }
            } catch (e: Exception) {
                _state.update {
                    it.copy(
                        busy = false,
                        errorMessage = e.message
                            ?: getApplication<Application>().getString(
                                com.myvault.password.R.string.error_unlock_failed,
                            ),
                    )
                }
            } finally {
                com.myvault.password.core.CryptoPrimitives.destroy(password)
            }
        }
    }

    /** 指纹流程成功后由界面把解出的数据密钥交给这里。 */
    fun unlockWithBiometricKey(dataKey: ByteArray) {
        viewModelScope.launch {
            _state.update { it.copy(busy = true, errorMessage = null) }
            try {
                repository.unlockWithBiometricKey(dataKey)
                onUnlocked()
            } catch (e: Exception) {
                _state.update {
                    it.copy(
                        busy = false,
                        errorMessage = e.message
                            ?: getApplication<Application>().getString(
                                com.myvault.password.R.string.error_biometric_unlock_failed,
                            ),
                    )
                }
            } finally {
                com.myvault.password.core.CryptoPrimitives.destroy(dataKey)
            }
        }
    }

    private fun onUnlocked() {
        _state.update { it.copy(busy = false, errorMessage = null) }
        // 解锁即视为一次交互：闲置超时从「解锁这一刻」开始计时，
        // 否则本次会话会立刻被判为闲置。
        autoLockSession.markSessionStart()
        appInForeground = true
        startCollecting()
        startForegroundWatchdog()
    }

    private fun startCollecting() {
        collectJob?.cancel()
        collectJob = viewModelScope.launch {
            repository.observeDecodeResults().collect { result ->
                _state.update { state ->
                    state.copy(
                        lockState = LockState.Unlocked(repository.currentEnvelope?.keyId ?: ""),
                        entries = result.entries,
                        brokenEntryIds = result.brokenEntryIds,
                    )
                }
            }
        }
    }

    /**
     * 清理无法解密的条目。
     *
     * 这些记录已经不可恢复（密文无法通过认证），保留它们只会让列表
     * 反复提示错误。界面上需要二次确认。
     */
    fun deleteBrokenEntries() {
        val ids = _state.value.brokenEntryIds
        if (ids.isEmpty()) return
        viewModelScope.launch {
            ids.forEach { repository.deleteEntry(it) }
            _state.update { it.copy(brokenEntryIds = emptyList()) }
        }
    }

    fun lock() {
        viewModelScope.launch {
            collectJob?.cancel()
            collectJob = null
            // 看门狗必须随锁定一起停止，否则它会继续空转并在已锁定时反复判定
            stopForegroundWatchdog()
            // 锁定是绝对的：任何残留的会话保持都必须清掉。
            // 「自动锁定被永久关闭」比「多锁一次」严重得多。
            autoLockSession.clearHolds()
            ClipboardHelper.clearNow(getApplication())
            repository.lock()
            _state.update { it.copy(lockState = LockState.Locked, entries = emptyList(), query = "") }
        }
    }

    override fun onCleared() {
        stopForegroundWatchdog()
        super.onCleared()
    }

    // ------------------------------------------------------------ 生命周期 / 自动锁定

    /**
     * 应用当前是否在前台。
     *
     * 注意它与「用户是否还在使用」不是一回事：SAF 选择器会让我们进入后台，
     * 但用户并没有离开 —— 那一类情况由「会话保持」表达
     * （见 [com.myvault.password.core.AutoLockSession.HOLD_SYSTEM_PICKER]），
     * 而不是在这里伪造一个前台状态。
     */
    @Volatile
    private var appInForeground: Boolean = true

    private var foregroundWatchdog: Job? = null

    /**
     * 用户产生了交互（点击、输入、滚动）。
     *
     * 由界面层在**所有能观察到用户的地方**调用：
     *  - 已解锁界面根容器上的 `pointerInput`（触摸）；
     *  - 对话框（它们是独立窗口，根容器收不到那里的触摸）；
     *  - 文字输入（软键盘（IME）提交文字**不会**产生任何指针事件）。
     *
     * 遗漏任何一处都会重现「正在操作却被锁」的缺陷 —— 后两处就是这么漏掉的。
     */
    fun onUserInteraction() {
        autoLockSession.onUserInteraction()
    }

    fun onEnterBackground() {
        appInForeground = false
    }

    /**
     * 回到前台。
     *
     * 判定「离开期间是否已超时」，超时则立即锁定（这样用户看不到任何内容闪现）。
     * 关键点：[AutoLockSession.markSessionStart] 在这里被调用，
     * 否则「离开 2 小时」这一事实会让刚回到前台的用户被立刻再次锁定。
     *
     * 若此刻有会话保持（例如刚从文件选择器回来），判定结果为「不锁」——
     * 这次「回到前台」只是选择器关闭，不是用户离开过。
     */
    fun onEnterForeground() {
        appInForeground = true
        viewModelScope.launch {
            val configured = settings.current().autoLockMillis
            val shouldLockNow = autoLockSession.shouldLock(
                configuredMillis = configured,
                inForeground = true,
            )
            // 回到前台先重置基准：本次会话的闲置时间从「现在」重新开始计算
            autoLockSession.markSessionStart()
            if (shouldLockNow) lock()
        }
    }

    private companion object {
        /**
         * 前台看门狗轮询间隔。
         *
         * 取 5 秒是刻意权衡：轮询本身不持有任何敏感数据，代价极低；
         * 而 5 秒的粒度对「闲置超时」这种以十秒/分钟计的策略完全够用。
         * 不要把它做成每帧或每秒级 —— 那既浪费电，也增加误锁窗口。
         */
        const val FOREGROUND_WATCHDOG_INTERVAL_MS = 5_000L
    }

    /**
     * 前台闲置看门狗。
     *
     * 取代了原先「解锁时启动一次性 delay」的错误实现，现在的语义是：
     * **在用户持续操作期间永不锁定；只有在连续 [VaultSettings.autoLockMillis]
     * 没有任何交互时才锁定。**
     *
     * 判定本身全部交给 [AutoLockSession]（它同时掌握交互时间与进行中的流程），
     * 这里只负责按固定间隔问一次 —— 判定逻辑不在这段循环里，避免出现
     * 「看门狗与回到前台各判一套、结果不一致」。
     */
    private fun startForegroundWatchdog() {
        foregroundWatchdog?.cancel()
        foregroundWatchdog = viewModelScope.launch {
            while (isActive) {
                delay(FOREGROUND_WATCHDOG_INTERVAL_MS)
                if (_state.value.lockState !is LockState.Unlocked) continue
                val configured = settings.current().autoLockMillis
                if (autoLockSession.shouldLock(configured, inForeground = appInForeground)) {
                    lock()
                    return@launch
                }
            }
        }
    }

    private fun stopForegroundWatchdog() {
        foregroundWatchdog?.cancel()
        foregroundWatchdog = null
    }

    // ------------------------------------------------------------ 搜索

    fun setQuery(q: String) = _state.update { it.copy(query = q) }

    // ------------------------------------------------------------ 条目操作

    fun deleteEntry(id: String) {
        // 名称必须在删除**之前**取出来：删除后条目已不在列表里，
        // 而日志要记的正是「删掉的是哪一个」。
        val site = _state.value.entries.firstOrNull { it.id == id }?.displayTitle
        viewModelScope.launch {
            try {
                repository.deleteEntry(id)
                // 删除是审计意义上最重要的操作之一（可能是别人拿着解锁中的手机干的），因此必须留痕
                container.operationLog.logEntryDeleted(site, inDetailScreen = false)
                _state.update {
                    it.copy(message = getApplication<Application>().getString(
                        com.myvault.password.R.string.entry_deleted,
                    ))
                }
            } catch (e: Exception) {
                _state.update { it.copy(errorMessage = e.message) }
            }
        }
    }

    fun toggleFavorite(entry: VaultEntry) {
        viewModelScope.launch { repository.setFavorite(entry.id, !entry.favorite) }
    }

    /**
     * 复制字段到剪贴板（按设置自动清除）。密码标记为敏感内容。
     */
    fun copyField(entryId: String, value: String, sensitive: Boolean) {
        val app = getApplication<Application>()
        viewModelScope.launch {
            val clearAfter = settings.current().clipboardClearMillis
            val seconds = (clearAfter / 1000).toInt()
            ClipboardHelper.copy(
                context = app,
                label = "MyVault",
                text = value,
                sensitive = sensitive,
                clearAfterMillis = clearAfter,
            ) {
                _state.update { it.copy(copiedEntryId = null) }
            }
            _state.update {
                it.copy(
                    copiedEntryId = if (sensitive) entryId else null,
                    message = if (sensitive && seconds > 0) {
                        app.getString(com.myvault.password.R.string.entry_copied, seconds)
                    } else {
                        null
                    },
                )
            }
        }
    }

    fun consumeMessage() = _state.update { it.copy(message = null, errorMessage = null) }

    // ------------------------------------------------------------ 密码生成

    /** 生成一个符合策略的密码；策略非法时返回 null 并给出提示。 */
    suspend fun generatePassword(policy: PasswordPolicy): String? = withContext(Dispatchers.Default) {
        try {
            generator.generate(policy)
        } catch (e: IllegalArgumentException) {
            _state.update { it.copy(errorMessage = e.message) }
            null
        }
    }

    /** 新条目默认使用的策略（与生成器页面共享同一份定义）。 */
    fun defaultPolicy(): PasswordPolicy = PasswordPolicy(
        mode = PasswordPolicy.Mode.RANDOM,
        length = com.myvault.password.BuildConfig.DEFAULT_PASSWORD_LENGTH,
    )

    /** 供设置页展示的当前库内条目数。 */
    fun entryCount(): Int = _state.value.entries.size

    /** 熵信息，供生成器界面展示。 */
    fun entropyBits(policy: PasswordPolicy): Double = PasswordEntropy.bitsOf(policy)
}
