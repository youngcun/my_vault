package com.myvault.password.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.myvault.password.AppContainer
import com.myvault.password.core.PasswordEntropy
import com.myvault.password.core.LocaleController
import com.myvault.password.core.PolicyError
import com.myvault.password.core.PasswordPolicy
import com.myvault.password.core.WrongSecretException
import com.myvault.password.domain.VaultEntry
import com.myvault.password.settings.AppLanguage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** 条目编辑状态。 */
data class EntryEditState(
    val loading: Boolean = true,
    val entry: VaultEntry = VaultEntry.empty(),
    val isNew: Boolean = true,
    val passwordVisible: Boolean = false,
    val lastGeneratedPlain: String? = null,
    /**
     * 密码是否被改动过（相对打开编辑界面时该条目的原密码）。
     *
     * 界面据此在保存前插入一次二次确认，并在确认框里点出**当前条目的应用名称**，
     * 避免在错误的条目上覆盖密码。新建条目恒为 false。
     * 判定规则本身在 [EntryEditRules.passwordChangedDuringEdit]（纯函数，有单测）。
     */
    val passwordChanged: Boolean = false,
    val policy: PasswordPolicy = PasswordPolicy(),
    val error: String? = null,
    /**
     * 生成器策略不可行的原因。
     *
     * 刻意存**结构化原因**而不是已经渲染好的文案：文案必须按当前语言在
     * 显示时解析，否则用户切换语言后，还挂在状态里的旧提示会留在旧语言上。
     */
    val policyError: PolicyError? = null,
    val saved: Boolean = false,
    val deleted: Boolean = false,
    /** 保存/删除进行中：用于禁用按钮并显示进度，避免重复提交与「点了没反应」的错觉。 */
    val working: Boolean = false,
) {
    val titleRes: Int
        get() = if (isNew) com.myvault.password.R.string.entry_new_title
        else com.myvault.password.R.string.entry_edit_title
}

/**
 * 条目编辑 ViewModel。
 *
 * @param entryId 为 null 时表示新建。
 * @param prefillPackage 新建时的「应用包名」预填值。来自自动填充的
 *   「库里没有匹配条目」卡片：用户点一下就能为当前 App 建条目，
 *   而不必自己去查这个 App 的包名是什么。
 * @param prefillDomain 新建时的站点预填值（浏览器场景的域名）。
 */
class EntryEditViewModel(
    app: Application,
    private val entryId: String?,
    private val prefillPackage: String? = null,
    private val prefillDomain: String? = null,
) : AndroidViewModel(app) {

    private val container = AppContainer.from(app)
    private val repository = container.repository
    private val generator = container.passwordGenerator
    private val operationLog = container.operationLog

    private val _state = MutableStateFlow(EntryEditState())
    val state: StateFlow<EntryEditState> = _state.asStateFlow()

    /**
     * 打开编辑界面时该条目的原始站点名称。
     *
     * 用来判断「这次保存是否真的改了名称」：如果不记下原值，
     * 就无法区分「用户改了名字」和「用户只是改了密码又保存了一次」，
     * 日志会被无意义的改名记录淹没。
     */
    private var originalSite: String? = null

    /**
     * 打开编辑界面时该条目的密码原文。
     *
     * 只用于判断「这一次保存是否真的改了密码」（见 [EntryEditState.passwordChanged]），
     * 从不回显到界面 —— 界面显示的一律是 [EntryEditState.entry] 里当前正在编辑的值。
     * 新建条目为 null：那时不存在「原来的密码」可覆盖。
     */
    private var originalPassword: String? = null

    init {
        viewModelScope.launch {
            if (entryId == null) {
                // 新建：直接生成一个高强度初始密码，省去用户「先想一个」的坏习惯
                val policy = PasswordPolicy(
                    length = com.myvault.password.BuildConfig.DEFAULT_PASSWORD_LENGTH,
                )
                val generated = runCatching { generator.generate(policy) }.getOrNull()
                _state.update {
                    it.copy(
                        loading = false,
                        isNew = true,
                        entry = VaultEntry.empty().copy(
                            password = generated.orEmpty(),
                            generated = true,
                            // 预填线索：域名进「站点」，包名进「网址」
                            // （网址字段同时充当「应用包名」，见 VaultEntry.matchScore）
                            site = prefillDomain.orEmpty(),
                            url = prefillPackage.orEmpty(),
                        ),
                        policy = policy,
                        lastGeneratedPlain = generated,
                    )
                }
            } else {
                val existing = repository.findEntry(entryId)
                // 原名称只在真正读到条目时记录：读不到（例如条目已损坏）时
                // 不该把 null 当成「用户把名字改成了空」这类噪音记录进日志。
                originalSite = existing?.site
                // 同理，原密码只在读到条目时才有得比；读不到时保持 null，
                // 也就不会因为「空 vs 输入值」误判成一次改密。
                originalPassword = existing?.password
                _state.update {
                    it.copy(
                        loading = false,
                        isNew = false,
                        entry = existing ?: VaultEntry.empty().copy(id = entryId),
                    ).withPasswordChangeFlag()
                }
            }
        }
    }

    fun updateSite(value: String) = editEntry { entry -> entry.copy(site = value) }
    fun updateUsername(value: String) = editEntry { entry -> entry.copy(username = value) }
    fun updateUrl(value: String) = editEntry { entry -> entry.copy(url = value) }
    fun updateNotes(value: String) = editEntry { entry -> entry.copy(notes = value) }

    /** 用户手动改密码 → 视为「非生成」密码。 */
    fun updatePassword(value: String) = editEntry { entry ->
        entry.copy(password = value, generated = false)
    }

    fun togglePasswordVisible() = mutate { state -> state.copy(passwordVisible = !state.passwordVisible) }

    fun toggleFavorite() = editEntry { entry -> entry.copy(favorite = !entry.favorite) }

    fun updatePolicy(policy: PasswordPolicy) = mutate { state -> state.copy(policy = policy) }

    /**
     * 只修改条目字段的辅助函数。
     *
     * 这里显式命名 lambda 参数（而不是用 `it`）是必要的：Kotlin 里嵌套 lambda
     * 的隐式 `it` 会被内层遮蔽，极易写成「对外层状态调用 copy」这种错误，
     * 而且编译器的报错信息（No parameter with name 'site'）并不会直接指向根因。
     *
     * 每次改动后都重算一次 [EntryEditState.passwordChanged]：把同步放在这个
     * 唯一入口里，而不是只加在 [updatePassword] 中 —— 将来任何新的「写密码」
     * 入口都自动继承这条规则，不会出现「改了密码却不二次确认」的静默缺口。
     */
    private inline fun editEntry(block: (VaultEntry) -> VaultEntry) {
        _state.update { state -> state.copy(entry = block(state.entry)).withPasswordChangeFlag() }
    }

    /**
     * 按 [EntryEditRules.passwordChangedDuringEdit] 重算「密码是否被改动」。
     *
     * 幂等：只用「原密码 vs 当前值」计算，与调用次数无关。
     */
    private fun EntryEditState.withPasswordChangeFlag(): EntryEditState = copy(
        passwordChanged = EntryEditRules.passwordChangedDuringEdit(
            isNew = isNew,
            originalPassword = originalPassword,
            currentPassword = entry.password,
        ),
    )

    /** 按当前策略重新生成密码并直接写入条目（密码字段可见，便于用户确认）。 */
    fun regenerate() {
        val policy = _state.value.policy
        viewModelScope.launch {
            try {
                val generated = generator.generate(policy)
                _state.update {
                    it.copy(
                        entry = it.entry.copy(password = generated, generated = true),
                        passwordVisible = true,
                        lastGeneratedPlain = generated,
                        error = null,
                        policyError = null,
                    ).withPasswordChangeFlag()
                }
            } catch (e: IllegalArgumentException) {
                // 文案由界面按当前语言渲染（见 EntryEditState.policyError 的说明）。
                _state.update { it.copy(policyError = policy.invalidReason()) }
            }
        }
    }

    fun entropyBits(): Double = PasswordEntropy.bitsOf(_state.value.policy)

    /**
     * 保存条目。
     *
     * 三条原则（都来自真实故障教训）：
     *  1. 校验失败要给出**具体原因**，而不是静默忽略点击；
     *  2. 异常必须落到 [EntryEditState.error] 并由界面显示 ——
     *     绝不吞掉，否则用户看到的就是「点了保存但没反应」；
     *  3. 用 [EntryEditState.working] 防止重复提交。
     */
    fun save() {
        if (_state.value.working) return
        val current = _state.value.entry
        val app = getApplication<Application>()
        if (current.site.isBlank()) {
            _state.update {
                it.copy(error = app.getString(com.myvault.password.R.string.entry_site_required))
            }
            return
        }
        if (current.password.isEmpty()) {
            _state.update {
                it.copy(error = app.getString(com.myvault.password.R.string.entry_password_required))
            }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(working = true, error = null) }
            try {
                val saved = repository.saveEntry(current.copy(updatedAt = System.currentTimeMillis()))
                // 保存后用同一条记录回读一次，确认它真的能被解开。
                // 这一步能立刻暴露「写入成功但读不回来」这类问题，
                // 而不是让用户回到列表才发现条目不见了。
                val verified = repository.findEntry(saved.id)
                if (verified == null) {
                    _state.update {
                        it.copy(
                            working = false,
                            error = app.getString(com.myvault.password.R.string.entry_save_unreadable),
                        )
                    }
                    return@launch
                }
                // 名称变更记入日志。
                //
                // 两点刻意的取舍：
                //  1. **只记真正的改名**（旧名 → 新名），不记新建条目。
                //     「新建时填了什么名字」可以从库里看到，记进日志只会把
                //     真正的改名记录淹掉 —— 日志的价值取决于信噪比。
                //  2. 只比较去首尾空格后的名称，避免「多敲了一个空格」
                //     也被记成一次改名。
                val previous = originalSite?.trim()
                val newName = saved.site.trim()
                if (!_state.value.isNew && previous != null && previous != newName) {
                    operationLog.logSiteRenamed(oldSite = previous, newSite = newName)
                    originalSite = newName
                }
                _state.update { it.copy(working = false, saved = true, error = null) }
            } catch (e: Exception) {
                _state.update {
                    it.copy(
                        working = false,
                        error = app.getString(
                            com.myvault.password.R.string.entry_save_failed,
                            e.message ?: e::class.java.simpleName,
                        ),
                    )
                }
            }
        }
    }

    fun delete() {
        if (_state.value.working) return
        val entry = _state.value.entry
        val app = getApplication<Application>()
        viewModelScope.launch {
            _state.update { it.copy(working = true, error = null) }
            try {
                repository.deleteEntry(entry.id)
                // 详情页的删除同样必须留痕：这是「整条凭据消失」的唯一途径
                operationLog.logEntryDeleted(entry.displayTitle, inDetailScreen = true)
                _state.update { it.copy(working = false, deleted = true) }
            } catch (e: Exception) {
                _state.update {
                    it.copy(
                        working = false,
                        error = e.message
                            ?: app.getString(com.myvault.password.R.string.error_delete_failed),
                    )
                }
            }
        }
    }

    fun consumeError() = mutate { it.copy(error = null, policyError = null) }

    private inline fun mutate(block: (EntryEditState) -> EntryEditState) {
        _state.update(block)
    }

    companion object {
        /**
         * 为 `viewModel(factory = ...)` 提供工厂。
         *
         * 刻意使用最朴素的 [androidx.lifecycle.ViewModelProvider.Factory] 实现，
         * 而不依赖 `viewModelFactory { initializer { ... } }` DSL：
         *  - 少一层 API 依赖，编译器版本变化不会影响构建；
         *  - 「ViewModel 需要哪些参数」在代码里是显式可读的。
         *
         * @param entryId 为 null 表示新建条目
         * @param prefillPackage / [prefillDomain] 见构造函数说明
         */
        fun factory(
            entryId: String?,
            prefillPackage: String? = null,
            prefillDomain: String? = null,
        ): androidx.lifecycle.ViewModelProvider.Factory =
            object : androidx.lifecycle.ViewModelProvider.Factory {
                override fun <T : androidx.lifecycle.ViewModel> create(
                    modelClass: Class<T>,
                    extras: androidx.lifecycle.viewmodel.CreationExtras,
                ): T {
                    val app = extras[androidx.lifecycle.ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY]
                        ?: error("缺少 Application，无法创建 EntryEditViewModel")
                    @Suppress("UNCHECKED_CAST")
                    return EntryEditViewModel(app, entryId, prefillPackage, prefillDomain) as T
                }
            }
    }
}

/** 设置界面状态。 */
data class SettingsState(
    val autoLockMillis: Long = 60_000L,
    val clipboardClearMillis: Long = 30_000L,
    val blockScreenshots: Boolean = true,
    val importOverwrite: Boolean = false,
    val biometricEnabled: Boolean = false,
    val biometricReady: Boolean = false,
    val entryCount: Int = 0,
    /**
     * 当前界面语言。
     *
     * 它不由 DataStore 推送，而是在 [SettingsViewModel] 里从
     * [com.myvault.password.core.LocaleController] 同步读取 ——
     * 语言切换会重建 Activity，因此每次重建时重新读一次即可，
     * 不需要一条额外的响应式通道。
     */
    val language: AppLanguage = AppLanguage.DEFAULT,
    val kdfDescription: String = "",
    val keyId: String = "",
    val message: String? = null,
    val error: String? = null,
    /** 修改主密码对话框是否打开。 */
    val changingPassword: Boolean = false,
    /** 导出备份对话框是否打开。 */
    val exporting: Boolean = false,
    val working: Boolean = false,
)

/**
 * 设置 ViewModel：安全策略、主密码修改、指纹开关、备份导入导出入口。
 *
 * 所有涉及密钥的操作（改密码、开关指纹）都必须重新提交主密码，
 * 这是有意为之：不能让「已经解锁的会话」成为绕过强认证的后门。
 */
class SettingsViewModel(app: Application) : AndroidViewModel(app) {

    private val container = AppContainer.from(app)
    private val repository = container.repository
    private val settingsStore = container.settings
    private val keystore = com.myvault.password.core.KeystoreManager()

    private val _state = MutableStateFlow(SettingsState())
    val state: StateFlow<SettingsState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            settingsStore.settings.collect { s ->
                _state.update {
                    it.copy(
                        autoLockMillis = s.autoLockMillis,
                        clipboardClearMillis = s.clipboardClearMillis,
                        blockScreenshots = s.blockScreenshots,
                        importOverwrite = s.importOverwrite,
                    )
                }
            }
        }
        // 语言不是 DataStore 设置：它必须能在 Application 启动期被同步应用，
        // 因此真值源是 LocaleController 的 SharedPreferences。这里只是把它
        // 读进界面状态，切换动作见 setLanguage。
        _state.update { it.copy(language = LocaleController.current(getApplication())) }
        refresh()
    }

    /**
     * 切换界面语言。
     *
     * 不需要在这里更新 [SettingsState.language]：LocaleController 会触发
     * Configuration 变化，Activity 随之重建，重建后 init 会重新读到新值。
     * 若这里再手动改一次状态，反而会与重建后的读取形成两个真值来源。
     */
    fun setLanguage(language: AppLanguage) {
        LocaleController.setLanguage(getApplication(), language)
    }

    fun refresh() {
        viewModelScope.launch {
            val envelope = repository.currentEnvelope
            val biometricReady = com.myvault.password.core.BiometricCapability
                .resolve(getApplication())
                .supportsCryptoObject
            _state.update {
                it.copy(
                    biometricEnabled = envelope?.biometricWrap != null,
                    biometricReady = biometricReady,
                    entryCount = repository.entryCount(),
                    kdfDescription = envelope?.describeKdf() ?: "",
                    keyId = envelope?.keyId?.take(8) ?: "",
                )
            }
        }
    }

    fun setAutoLock(millis: Long) {
        viewModelScope.launch {
            settingsStore.setAutoLockMillis(millis)
            _state.update { it.copy(autoLockMillis = millis) }
        }
    }

    fun setClipboardClear(millis: Long) {
        viewModelScope.launch {
            settingsStore.setClipboardClearMillis(millis)
            _state.update { it.copy(clipboardClearMillis = millis) }
        }
    }

    fun setBlockScreenshots(block: Boolean) {
        viewModelScope.launch {
            settingsStore.setBlockScreenshots(block)
            _state.update { it.copy(blockScreenshots = block) }
        }
    }

    fun setImportOverwrite(overwrite: Boolean) {
        viewModelScope.launch {
            settingsStore.setImportOverwrite(overwrite)
            _state.update { it.copy(importOverwrite = overwrite) }
        }
    }

    // ---------------------------------------------------------- 修改主密码

    fun openChangePassword() = _state.update { it.copy(changingPassword = true) }
    fun closeChangePassword() = _state.update { it.copy(changingPassword = false, error = null) }

    fun changeMasterPassword(current: CharArray, newPassword: CharArray) {
        val app = getApplication<Application>()
        viewModelScope.launch {
            _state.update { it.copy(working = true, error = null) }
            try {
                repository.changeMasterPassword(current, newPassword)
                // 只记录「改过密码」这一事实。刻意不传任何口令内容 ——
                // 日志是明文文件，一旦写入口令就等于把密码库降级成纯文本。
                container.operationLog.logMasterPasswordChanged()
                _state.update {
                    it.copy(
                        working = false,
                        changingPassword = false,
                        message = app.getString(com.myvault.password.R.string.settings_change_password_done),
                    )
                }
            } catch (e: WrongSecretException) {
                _state.update {
                    it.copy(
                        working = false,
                        error = app.getString(com.myvault.password.R.string.unlock_wrong_password),
                    )
                }
            } catch (e: Exception) {
                _state.update {
                    it.copy(
                        working = false,
                        error = app.getString(
                            com.myvault.password.R.string.settings_change_password_failed,
                            e.message ?: "",
                        ),
                    )
                }
            } finally {
                com.myvault.password.core.CryptoPrimitives.destroy(current, newPassword)
            }
        }
    }

    // ---------------------------------------------------------- 指纹

    /**
     * 开启指纹解锁。
     *
     * 流程：探测设备能力 → 用**与设备能力匹配的认证强度**创建 Keystore 密钥 →
     * 初始化加密 Cipher → 交给 BiometricPrompt 认证 → 认证成功后用它包裹 DEK 并写入信封。
     *
     * 为什么必须先探测能力（这是一个真实故障的修复）：
     * Android 的生物识别分 Class 3（STRONG，指纹/3D 人脸）与 Class 2（WEAK，多数 2D 人脸）。
     * **Class 2 不能用于加密绑定**。若把密钥强度写死为 STRONG，而设备只有 Class 2，
     * 就会出现「弹窗验证通过、但 CryptoObject 绑定失败」的诡异组合，
     * 系统提示 `Crypto-based authentication is not supported for Class 2 (Weak) biometrics`。
     *
     * 本应用的处理策略（安全优先）：
     *  - Class 3 可用 → 用它，可加密绑定；
     *  - 只有 Class 2 → **明确拒绝开启**，并解释原因。绝不用「降级到弱生物识别」假装成功，
     *    因为那样并不能真正保护数据；
     *  - 有设备凭据且系统支持（Android 11+）→ 用设备凭据绑定作为回退。
     *
     * @param onNeedBiometricCipher 界面在此回调里发起 BiometricPrompt 认证，
     *        并把通过认证的 Cipher 交回 [finishEnableBiometric]
     */
    fun beginEnableBiometric(password: CharArray, onNeedBiometricCipher: (javax.crypto.Cipher) -> Unit) {
        val app = getApplication<Application>()
        viewModelScope.launch {
            // 立刻置为进行中：用户点下开关后，即使紧接着弹出系统指纹框，
            // 界面也已经给出「正在处理」的反馈，不会出现「点了没反应」。
            _state.update { it.copy(working = true, error = null) }
            val config = com.myvault.password.core.BiometricCapability.resolve(app)
            if (!config.supportsCryptoObject) {
                com.myvault.password.core.CryptoPrimitives.destroy(password)
                val message = if (config.weakBiometricsOnly) {
                    app.getString(com.myvault.password.R.string.biometric_weak_only)
                } else {
                    app.getString(com.myvault.password.R.string.biometric_unavailable_for_crypto)
                }
                _state.update { it.copy(working = false, error = message) }
                return@launch
            }
            try {
                val suffix = java.util.UUID.randomUUID().toString().take(8)
                val alias = com.myvault.password.core.KeystoreManager.BIO_ALIAS_PREFIX + suffix
                // 强制重建密钥：这样旧版本遗留的密钥（时效型认证 / 写死 STRONG）
                // 会被自动替换掉，用户重新开启一次即可完成迁移，无需清除应用数据。
                val key = keystore.recreateAuthBoundKey(alias, config.authenticator)
                val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
                // 把口令与别名暂存，等认证通过后再真正落盘
                pendingEnable = PendingEnable(password.copyOf(), alias, suffix)
                // working 保持 true：接下来是系统指纹框 + 一次 Argon2id 重新封装，
                // 两段都还没有结果，界面应持续显示进行中。
                onNeedBiometricCipher(cipher)
            } catch (e: Exception) {
                com.myvault.password.core.CryptoPrimitives.destroy(password)
                _state.update {
                    it.copy(
                        working = false,
                        error = app.getString(
                            com.myvault.password.R.string.biometric_enroll_failed,
                            e.message ?: e::class.java.simpleName,
                        ),
                    )
                }
            }
        }
    }

    /** 供设置界面判断「指纹解锁」这一项是否可用，以及不可用的原因。 */
    suspend fun biometricSupportMessage(): String? {
        val app = getApplication<Application>()
        val config = com.myvault.password.core.BiometricCapability.resolve(app)
        return when {
            config.supportsCryptoObject -> null
            config.weakBiometricsOnly ->
                app.getString(com.myvault.password.R.string.biometric_weak_only)
            else ->
                app.getString(com.myvault.password.R.string.biometric_unavailable_for_crypto)
        }
    }

    private var pendingEnable: PendingEnable? = null

    private data class PendingEnable(
        val password: CharArray,
        val alias: String,
        val suffix: String,
    )

    /** 指纹验证成功后调用：用已认证的 cipher 包裹 DEK 并写入信封。 */
    fun finishEnableBiometric(authenticatedCipher: javax.crypto.Cipher) {
        val app = getApplication<Application>()
        val pending = pendingEnable ?: return
        pendingEnable = null
        viewModelScope.launch {
            _state.update { it.copy(working = true, error = null) }
            try {
                // 取出当前会话的数据密钥副本（Keystore 加密只能在 ViewModel 侧完成），
                // 加密后立即清零副本。
                val material = repository.sessionDataKeyCopy()
                    ?: throw IllegalStateException(
                        app.getString(com.myvault.password.R.string.error_vault_not_unlocked),
                    )
                val sealed = try {
                    keystore.seal(authenticatedCipher, material)
                } finally {
                    com.myvault.password.core.CryptoPrimitives.destroy(material)
                }
                repository.enableBiometric(pending.password, sealed, pending.suffix)
                _state.update {
                    it.copy(
                        working = false,
                        biometricEnabled = true,
                        message = app.getString(com.myvault.password.R.string.settings_biometric_summary_on),
                    )
                }
            } catch (e: Exception) {
                _state.update {
                    it.copy(
                        working = false,
                        error = e.message
                            ?: app.getString(
                                com.myvault.password.R.string.error_enable_biometric_failed,
                            ),
                    )
                }
            } finally {
                com.myvault.password.core.CryptoPrimitives.destroy(pending.password)
            }
        }
    }

    /** 指纹验证取消或失败。 */
    fun abortEnableBiometric() {
        pendingEnable?.let { com.myvault.password.core.CryptoPrimitives.destroy(it.password) }
        pendingEnable = null
        // 取消也必须复位进行中状态，否则开关会永远卡在「进行中」
        _state.update { it.copy(working = false) }
    }

    fun disableBiometric(password: CharArray) {
        val app = getApplication<Application>()
        viewModelScope.launch {
            _state.update { it.copy(working = true, error = null) }
            try {
                val suffix = repository.biometricAliasSuffix()
                repository.disableBiometric(password)
                if (suffix != null) {
                    keystore.deleteKey(com.myvault.password.core.KeystoreManager.BIO_ALIAS_PREFIX + suffix)
                }
                _state.update {
                    it.copy(
                        working = false,
                        biometricEnabled = false,
                        message = app.getString(com.myvault.password.R.string.settings_biometric_summary_off),
                    )
                }
            } catch (e: Exception) {
                _state.update {
                    it.copy(
                        working = false,
                        error = e.message
                            ?: app.getString(
                                com.myvault.password.R.string.error_disable_biometric_failed,
                            ),
                    )
                }
            } finally {
                com.myvault.password.core.CryptoPrimitives.destroy(password)
            }
        }
    }

    // ---------------------------------------------------------- 备份

    fun openExport() = _state.update { it.copy(exporting = true) }
    fun closeExport() = _state.update { it.copy(exporting = false) }

    suspend fun snapshotForBackup(): List<VaultEntry> = repository.snapshotForBackup()

    suspend fun restore(entries: List<VaultEntry>): com.myvault.password.operationlog.RestoreReport =
        repository.restoreEntries(entries, _state.value.importOverwrite)

    suspend fun currentSettings() = settingsStore.current()

    fun notify(message: String) = _state.update { it.copy(message = message) }

    fun notifyError(message: String) = _state.update { it.copy(error = message) }

    fun consumeMessages() = _state.update { it.copy(message = null, error = null) }
}
