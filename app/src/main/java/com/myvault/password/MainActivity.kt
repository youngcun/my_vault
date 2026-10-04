package com.myvault.password

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.myvault.password.backup.BackupManager
import com.myvault.password.core.AppLockGate
import com.myvault.password.core.AutoLockSession
import com.myvault.password.core.Base64Codec
import com.myvault.password.core.BiometricCapability
import com.myvault.password.core.CryptoPrimitives
import com.myvault.password.core.EnvelopeCodec
import com.myvault.password.core.KeystoreManager
import com.myvault.password.core.PasswordPolicy
import com.myvault.password.ui.AuditViewModel
import com.myvault.password.ui.EntryEditViewModel
import com.myvault.password.ui.LockState
import com.myvault.password.ui.MainViewModel
import com.myvault.password.ui.MainUiState
import com.myvault.password.ui.OperationLogViewModel
import com.myvault.password.ui.SettingsViewModel
import com.myvault.password.ui.components.LocalUserActivity
import com.myvault.password.ui.screens.AuditScreen
import com.myvault.password.ui.screens.EntryEditScreen
import com.myvault.password.ui.screens.GeneratorScreen
import com.myvault.password.ui.screens.LockScreen
import com.myvault.password.ui.screens.OperationLogScreen
import com.myvault.password.ui.screens.PasswordConfirmDialog
import com.myvault.password.ui.screens.SettingsScreen
import com.myvault.password.ui.screens.SetupScreen
import com.myvault.password.ui.screens.VaultListScreen
import com.myvault.password.ui.theme.MyVaultTheme
import com.myvault.password.util.ClipboardHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 自动填充卡片带过来的「新建条目」线索。
 *
 * 两者都可能为空：原生 App 只有包名，浏览器只有域名。
 */
private data class AutofillPrefill(
    val packageName: String = "",
    val webDomain: String = "",
)

/**
 * 主 Activity。
 *
 * 承担四类职责：
 *  1. 承载 Compose 导航；
 *  2. 根据设置动态开关 FLAG_SECURE（禁止截屏/录屏）；
 *  3. 驱动 BiometricPrompt（指纹解锁，以及「开启指纹」时的密钥认证）；
 *  4. 通过 SAF 完成备份文件的导入导出。
 *
 * 关于第 4 点：本应用**没有申请任何存储权限**。所有文件访问都必须由用户
 * 在系统文件选择器里显式授权一个 URI，SAF 返回的临时授权就是唯一的凭据。
 *
 * 继承 [AppCompatActivity] 是因为 androidx.biometric 的 BiometricPrompt
 * 需要 FragmentActivity 作为宿主。
 */
class MainActivity : AppCompatActivity() {

    private val container by lazy { AppContainer.from(this) }

    /** 导出流程中暂存的备份口令（在写文件后立即清零）。 */
    private var pendingExportPassphrase: CharArray? = null

    /** 待导入的备份文件 URI（等待用户输入备份口令）。 */
    private var pendingImportUri by mutableStateOf<Uri?>(null)

    /** 指纹相关的一次性提示消息。 */
    private var biometricMessage by mutableStateOf<String?>(null)

    /**
     * 自动填充「没有匹配条目」卡片带过来的新建条目线索。
     *
     * 用状态而不是直接读 Intent：库可能还锁着，此时不能立刻跳转 ——
     * 线索要留到用户解锁、进入列表之后再消费。
     */
    private var autofillPrefill by mutableStateOf<AutofillPrefill?>(null)

    // ------------------------------------------------------------ SAF

    /**
     * 导出：用户选定目标文件后写入加密备份。
     *
     * 关于 MIME 类型：这里用 `application/json` 而**不是**
     * `application/octet-stream`。原因很实际 —— 备份文件本身就是一个自包含的 JSON
     * （只有 `payload_enc` 是密文），而不少文件管理器/SAF 实现会依据 MIME 类型
     * 猜测或改写扩展名；用 `octet-stream` 时容易把 `.myvault` 后缀吞掉或改成 `.bin`，
     * 让用户拿到一个看不出是什么的文件。用 `application/json` 则不会干扰我们
     * 指定的文件名，同时仍然只是「提示类型」，不影响加密内容本身。
     *
     * 导出完成后会**回读系统实际使用的文件名**并告诉用户 ——
     * 用户可能在选择器里改过名字，报告真实结果比报告我们建议的名字更有用。
     */
    private val createBackupFile = registerForActivityResult(
        ActivityResultContracts.CreateDocument(BACKUP_MIME_TYPE),
    ) { uri: Uri? ->
        // 选择器已关闭：释放它申请的那一份会话保持（自动锁定判定随即恢复）
        releaseAutoLock(AutoLockSession.HOLD_SYSTEM_PICKER)

        val passphrase = pendingExportPassphrase
        pendingExportPassphrase = null
        if (uri == null) {
            // 用户取消：明确告知，不要静默返回（静默返回会让人以为导出成功了）
            CryptoPrimitives.destroy(passphrase)
            Toast.makeText(
                this@MainActivity,
                R.string.settings_export_cancelled,
                Toast.LENGTH_SHORT,
            ).show()
            return@registerForActivityResult
        }
        if (passphrase == null) {
            // 走到这里说明流程中间状态丢失（例如进程在选择器打开期间被系统回收）。
            // 必须给出可理解的原因，而不是「什么都没发生」。
            Toast.makeText(
                this@MainActivity,
                R.string.settings_export_interrupted,
                Toast.LENGTH_LONG,
            ).show()
            return@registerForActivityResult
        }

        lifecycleScope.launch {
            // 写备份这一步同样申请会话保持：快照解密 + Argon2id 需要数秒，
            // 期间用户不会碰屏幕，但这不是「闲置」—— 他是点完导出在等结果。
            // 在 finally 中释放：任何异常路径都不会留下永不释放的保持
            // （残留保持 = 自动锁定被永久关闭，比多锁一次严重得多）。
            val result = try {
                holdAutoLock(AutoLockSession.HOLD_BACKUP_IO)
                withContext(Dispatchers.IO) {
                    runCatching {
                        if (!container.repository.isUnlocked) {
                            error(getString(R.string.error_vault_locked))
                        }
                        val entries = container.repository.snapshotForBackup()
                        contentResolver.openOutputStream(uri)?.use { out ->
                            container.backupManager.export(
                                output = out,
                                entries = entries,
                                passphrase = passphrase,
                                appVersion = BuildConfig.VERSION_NAME,
                            )
                        } ?: error(getString(R.string.error_cannot_write_location))
                        // 回读实际落盘的文件名与大小，作为导出成功的证据
                        ExportReceipt(
                            fileName = resolveDisplayName(uri),
                            sizeBytes = resolveSize(uri),
                            entryCount = entries.size,
                        )
                    }
                }
            } finally {
                releaseAutoLock(AutoLockSession.HOLD_BACKUP_IO)
            }
            CryptoPrimitives.destroy(passphrase)
            result.onSuccess { receipt ->
                // 导出成功才记日志：一次失败的导出什么都没产生，
                // 把它写进日志只会让「日志里写着导出过，可文件在哪」变成新的困惑。
                container.operationLog.logBackupExported(
                    entryCount = receipt.entryCount,
                    fileName = receipt.fileName,
                )
                Toast.makeText(
                    this@MainActivity,
                    getString(
                        R.string.settings_export_done_named,
                        receipt.fileName ?: getString(R.string.settings_export_unknown_name),
                        formatBytes(receipt.sizeBytes),
                    ),
                    Toast.LENGTH_LONG,
                ).show()
            }.onFailure { e ->
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.settings_export_failed, e.message ?: ""),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    // ------------------------------------------------------------ 会话保持

    /**
     * 申请 / 释放「暂停自动锁定」。
     *
     * 走容器里那份共享的会话状态，而不是通过 Compose 在组合期注册的回调 ——
     * 那条桥在第一次选择器返回后被置空，导致**同一个解锁会话里的第二次导出
     * 完全没有豁免**，用户还在挑保存目录时密码库就被锁了（缺陷 #24）。
     * 容器实例与 Application 同生命周期，Activity 与 ViewModel 直接读写同一份状态。
     */
    private fun holdAutoLock(reason: String) {
        container.autoLockSession.hold(reason)
    }

    private fun releaseAutoLock(reason: String) {
        container.autoLockSession.release(reason)
    }

    /**
     * 打开「选择保存位置」的系统选择器。
     *
     * **必须先申请会话保持**：选择器是另一个 Activity，打开它会让本应用进入后台，
     * 而用户并没有离开 —— 他正在挑目录。保持一直持续到选择器返回
     * （见 [createBackupFile] 回调的第一行）。
     */
    private fun launchBackupPicker() {
        holdAutoLock(AutoLockSession.HOLD_SYSTEM_PICKER)
        runCatching { createBackupFile.launch(BackupManager.suggestFileName()) }
            .onFailure { e ->
                // 选择器打不开（例如系统概览缺失）：必须把保持和暂存的口令都收回来
                releaseAutoLock(AutoLockSession.HOLD_SYSTEM_PICKER)
                CryptoPrimitives.destroy(pendingExportPassphrase)
                pendingExportPassphrase = null
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.settings_export_failed, e.message ?: ""),
                    Toast.LENGTH_LONG,
                ).show()
            }
    }

    /** 导出结果凭证：实际文件名、字节数与条目数。 */
    private data class ExportReceipt(
        val fileName: String?,
        val sizeBytes: Long,
        /** 写进备份的条目数，用于操作日志（让用户事后知道那份备份里有什么）。 */
        val entryCount: Int,
    )

    /**
     * 从 SAF 返回的 URI 解析出展示用文件名。
     *
     * 为什么不显示「完整路径」：Android 的存储访问框架（SAF）有意**不暴露**
     * 真实绝对路径 —— 返回的 URI 形如
     * `content://com.android.providers.downloads.documents/document/1000000123`，
     * 其中的数字是文档 ID，不是路径。这是从 Android 10 起的分区存储设计，
     * 应用无法也不应绕过。
     *
     * 因此诚实的做法是：告诉用户**文件名 + 该文件位于他刚才选择的位置**，
     * 并保留原始 URI 供需要时查看，而不是伪造一个看似精确的路径。
     */
    private fun resolveDisplayName(uri: Uri): String? = runCatching {
        queryDocumentColumn(uri, android.provider.OpenableColumns.DISPLAY_NAME)
    }.getOrNull()

    private fun resolveSize(uri: Uri): Long = runCatching {
        queryDocumentColumn(uri, android.provider.OpenableColumns.SIZE)?.toLongOrNull() ?: -1L
    }.getOrDefault(-1L)

    private fun queryDocumentColumn(uri: Uri, column: String): String? =
        contentResolver.query(uri, arrayOf(column), null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(column)
            if (index >= 0 && cursor.moveToFirst() && !cursor.isNull(index)) {
                cursor.getString(index)
            } else {
                null
            }
        }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 0 -> "—"
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
        else -> "%.2f MB".format(bytes / (1024.0 * 1024.0))
    }

    /** 导入：选择备份文件。 */
    private val openBackupFile = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        // 选择器已关闭：释放它申请的那一份会话保持。
        // 之后用户在对话框里输入备份口令，靠「文字输入即交互」维持会话 ——
        // 软键盘（IME）提交文字不会产生任何指针事件，因此那一处必须单独上报。
        releaseAutoLock(AutoLockSession.HOLD_SYSTEM_PICKER)
        if (uri == null) {
            Toast.makeText(
                this@MainActivity,
                R.string.settings_import_cancelled,
                Toast.LENGTH_SHORT,
            ).show()
        } else {
            pendingImportUri = uri
        }
    }

    // ------------------------------------------------------------ 生命周期

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // 自动填充卡片可以拉起本界面（它是 singleTask），线索要在首帧之前就读出来
        consumeAutofillPrefill(intent)

        // 截屏保护默认开启；随后由设置流实时纠正。
        // 采集失败时保持「安全」的默认值：宁可用户看不到截图，也不要静默失去保护。
        applySecureFlag(secure = true)
        lifecycleScope.launch {
            runCatching {
                container.settings.settings.collect { s -> applySecureFlag(s.blockScreenshots) }
            }.onFailure { e ->
                android.util.Log.w("MyVault", "读取设置失败，保持截屏保护默认值", e)
            }
        }

        setContent {
            MyVaultTheme {
                VaultApp(
                    activity = this,
                    container = container,
                    biometricMessage = biometricMessage,
                    pendingImportUri = pendingImportUri,
                    onClearImport = { pendingImportUri = null },
                    onImportPassphrase = { uri, pwd -> performImport(uri, pwd) },
                    onCreateBackupFile = { passphrase, isMasterPassword ->
                        if (isMasterPassword) {
                            // 用户选择了「使用主密码作为备份口令」：
                            // **必须先校验**。否则一旦打错，备份会被一个错误口令加密，
                            // 等真正需要恢复时才发现打不开 —— 那时数据已经找不回来了。
                            lifecycleScope.launch {
                                val ok = withContext(Dispatchers.IO) {
                                    container.repository.verifyMasterPassword(passphrase)
                                }
                                if (!ok) {
                                    CryptoPrimitives.destroy(passphrase)
                                    Toast.makeText(
                                        this@MainActivity,
                                        R.string.settings_backup_master_wrong,
                                        Toast.LENGTH_LONG,
                                    ).show()
                                    return@launch
                                }
                                pendingExportPassphrase = passphrase
                                launchBackupPicker()
                            }
                        } else {
                            pendingExportPassphrase = passphrase
                            launchBackupPicker()
                        }
                    },
                    onPickBackupFile = {
                        // 与导出同理：选择备份文件时库绝不能被自动锁定。
                        // 保持由 openBackupFile 的回调释放。
                        holdAutoLock(AutoLockSession.HOLD_SYSTEM_PICKER)
                        runCatching { openBackupFile.launch(arrayOf("*/*")) }
                            .onFailure {
                                releaseAutoLock(AutoLockSession.HOLD_SYSTEM_PICKER)
                                Toast.makeText(
                                    this@MainActivity,
                                    getString(
                                        R.string.settings_import_failed,
                                        it.message ?: "",
                                    ),
                                    Toast.LENGTH_LONG,
                                ).show()
                            }
                    },
                    onBiometricMessage = { biometricMessage = it },
                    autofillPrefill = autofillPrefill,
                    onConsumeAutofillPrefill = { autofillPrefill = null },
                )
            }
        }
    }

    /**
     * 自动填充卡片已经打开着本界面时，Intent 会走这里而不是 [onCreate]。
     *
     * 必须调用 `setIntent`：否则后续 `getIntent()` 仍然返回旧的 Intent，
     * 二次进入时会拿着上一次的包名去预填。
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        consumeAutofillPrefill(intent)
    }

    /**
     * 从自动填充带来的一次性线索中提取包名与域名。
     *
     * 只接受「确实带了标识」的 Intent：点桌面图标启动时两个 extra 都不存在，
     * 此时绝不能把用户直接推进「新建条目」界面。
     */
    private fun consumeAutofillPrefill(intent: Intent?) {
        val pkg = intent?.getStringExtra(EXTRA_AUTOFILL_PACKAGE).orEmpty()
        val domain = intent?.getStringExtra(EXTRA_AUTOFILL_WEB_DOMAIN).orEmpty()
        if (pkg.isBlank() && domain.isBlank()) return
        autofillPrefill = AutofillPrefill(packageName = pkg, webDomain = domain)
    }

    override fun onDestroy() {
        // Activity 一旦销毁，它发起的流程不可能再完成 —— 必须把会话保持全部收回。
        // 「自动锁定被永久关闭」比「多锁一次」严重得多。
        container.autoLockSession.clearHolds()
        CryptoPrimitives.destroy(pendingExportPassphrase)
        pendingExportPassphrase = null
        ClipboardHelper.clearNow(this)
        super.onDestroy()
    }

    private fun applySecureFlag(secure: Boolean) {
        if (secure) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    // ------------------------------------------------------------ 备份导入

    private fun performImport(uri: Uri, passphrase: CharArray) {
        lifecycleScope.launch {
            // 读文件 + Argon2id + 解密 + 逐条写入同样不是「闲置」：
            // 期间用户只是在等结果。保持必须在 finally 中释放。
            val result = try {
                holdAutoLock(AutoLockSession.HOLD_BACKUP_IO)
                withContext(Dispatchers.IO) {
                    runCatching {
                        if (!container.repository.isUnlocked) {
                            error(getString(R.string.error_vault_locked))
                        }
                        val entries = contentResolver.openInputStream(uri)?.use { input ->
                            container.backupManager.import(input, passphrase)
                        } ?: error(getString(R.string.error_cannot_read_file))
                        // 恢复结果里带着「哪些名称重名」——它要被记进日志并提示用户。
                        // 文件名同样回读：日志里只写「导入过」而不写「从哪个文件导入」，
                        // 事后根本无法判断这次恢复到底用的是哪一份备份。
                        ImportReceipt(
                            fileName = resolveDisplayName(uri),
                            report = container.repository.restoreEntries(
                                entries = entries,
                                overwriteExisting = container.settings.current().importOverwrite,
                            ),
                        )
                    }
                }
            } finally {
                releaseAutoLock(AutoLockSession.HOLD_BACKUP_IO)
            }
            CryptoPrimitives.destroy(passphrase)
            result.onSuccess { receipt ->
                container.operationLog.logBackupRestored(
                    fileName = receipt.fileName,
                    report = receipt.report,
                )
                Toast.makeText(
                    this@MainActivity,
                    if (receipt.report.hasDuplicates) {
                        // 重名必须出现在用户眼前，而不只是安静地写进日志：
                        // 「同一站点两条记录」是用户需要立刻决定怎么处理的状态。
                        // 列表只列前几个名字，避免提示被截断得看不出所以然。
                        val names = receipt.report.duplicateSiteNames.take(3).joinToString("、")
                        val suffix = if (receipt.report.duplicateSiteNames.size > 3) "…" else ""
                        getString(
                            R.string.settings_import_done_duplicates,
                            receipt.report.imported,
                            receipt.report.skipped,
                            names + suffix,
                        )
                    } else {
                        getString(
                            R.string.settings_import_done,
                            receipt.report.imported,
                            receipt.report.skipped,
                        )
                    },
                    Toast.LENGTH_LONG,
                ).show()
            }.onFailure { e ->
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.settings_import_failed, e.message ?: ""),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    /** 导入结果凭证：文件名 + 恢复报告（含重名列表）。 */
    private data class ImportReceipt(
        val fileName: String?,
        val report: com.myvault.password.operationlog.RestoreReport,
    )

    // ------------------------------------------------------------ 指纹

    /**
     * 指纹解锁。
     *
     * 流程：从 Keystore 取回生物识别密钥 → 用信封中记录的 IV 初始化
     * DECRYPT 模式的 Cipher → 交给 BiometricPrompt 认证 → 认证成功后
     * 用**同一个** Cipher 解出数据密钥。
     *
     * 关键点：`setUserAuthenticationRequired(true)` + 时效 0 让这把密钥
     * **每次操作都需要认证**；只有系统确认指纹通过后，才会「解锁」这个 Cipher 实例。
     * 因此即便攻击者拿到应用沙箱内的全部文件，也解不出数据密钥。
     *
     * 错误处理：如果密钥是旧版本用「时效型认证」创建的，`cipher.init` 会抛
     * `UserNotAuthenticatedException`。此时给出明确指引（重新开启指纹解锁），
     * 而不是丢一句看不懂的英文异常。
     */
    fun promptBiometricUnlock(onKey: (ByteArray) -> Unit, onError: (String) -> Unit) {
        lifecycleScope.launch {
            val env = withContext(Dispatchers.IO) {
                runCatching {
                    val row = container.dao.loadEnvelope() ?: return@runCatching null
                    EnvelopeCodec.fromJson(row.json)
                }.getOrNull()
            }
            if (env == null || env.biometricWrap.isNullOrBlank() || env.biometricAlias.isNullOrBlank()) {
                onError(getString(R.string.unlock_biometric_failed))
                return@launch
            }
            val sealed = runCatching { Base64Codec.decode(env.biometricWrap!!) }.getOrNull()
            if (sealed == null) {
                onError(getString(R.string.unlock_biometric_failed))
                return@launch
            }
            val alias = KeystoreManager.BIO_ALIAS_PREFIX + env.biometricAlias
            val opened = runCatching { KeystoreManager().openCipherForDecrypt(alias, sealed) }
            if (opened.isFailure) {
                val cause = opened.exceptionOrNull()
                onError(
                    if (cause is java.lang.IllegalStateException) {
                        // 找不到密钥：指纹集合可能变化过，或数据被清理
                        getString(R.string.biometric_needs_reenroll)
                    } else {
                        getString(R.string.unlock_biometric_failed)
                    },
                )
                return@launch
            }
            val (cipher, body) = opened.getOrThrow()

            authenticate(
                title = getString(R.string.unlock_biometric_title),
                subtitle = getString(R.string.unlock_biometric_subtitle),
                cipher = cipher,
                onAuthenticated = { authedCipher ->
                    runCatching { authedCipher.doFinal(body) }
                        .onSuccess(onKey)
                        .onFailure { e ->
                            onError(
                                if (KeystoreManager().isPermanentlyInvalidated(e)) {
                                    getString(R.string.biometric_needs_reenroll)
                                } else {
                                    getString(R.string.unlock_biometric_failed)
                                },
                            )
                        }
                },
                onFailed = { msg ->
                    onError(
                        if (msg.contains("not authen", ignoreCase = true)) {
                            getString(R.string.biometric_needs_reenroll)
                        } else {
                            msg
                        },
                    )
                },
            )
        }
    }

    /**
     * 「开启指纹解锁」的第二步：对已经初始化好的加密 Cipher 做一次用户认证。
     *
     * 之所以由 Activity 持有这个流程：只有 Activity 能创建 BiometricPrompt。
     * ViewModel 负责密钥逻辑，Activity 负责用户交互，职责清晰。
     */
    fun promptBiometricEnrollWith(
        cipher: javax.crypto.Cipher,
        onAuthenticated: (javax.crypto.Cipher) -> Unit,
        onCancelled: () -> Unit = {},
    ) {
        authenticate(
            title = getString(R.string.settings_biometric),
            subtitle = getString(R.string.unlock_biometric_subtitle),
            cipher = cipher,
            onAuthenticated = onAuthenticated,
            onFailed = { msg ->
                Toast.makeText(this@MainActivity, msg, Toast.LENGTH_LONG).show()
                onCancelled()
            },
            onCancelled = onCancelled,
        )
    }

    /** 统一的 BiometricPrompt 调用（CryptoObject 模式）。
     *
     * 认证方式必须由 [com.myvault.password.core.BiometricCapability] 按设备实际能力给出，
     * 且必须与创建 Keystore 密钥时声明的强度**一致** —— 否则会出现
     * 「弹窗验证通过但绑定失败」（Class 2 生物识别的典型症状）。
     *
     * @param onCancelled 用户主动取消时回调。**必须复位「进行中」状态**，
     *   否则开关会永远显示进度圈。
     */
    private fun authenticate(
        title: String,
        subtitle: String,
        cipher: javax.crypto.Cipher,
        onAuthenticated: (javax.crypto.Cipher) -> Unit,
        onFailed: (String) -> Unit,
        onCancelled: () -> Unit = {},
    ) {
        val config = BiometricCapability.resolve(this)
        if (!config.supportsCryptoObject) {
            onFailed(
                getString(
                    if (config.weakBiometricsOnly) {
                        R.string.biometric_weak_only
                    } else {
                        R.string.biometric_unavailable_for_crypto
                    },
                ),
            )
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authed = result.cryptoObject?.cipher
                    if (authed == null) {
                        onFailed(getString(R.string.unlock_biometric_failed))
                    } else {
                        onAuthenticated(authed)
                    }
                }

                override fun onAuthenticationError(code: Int, errString: CharSequence) {
                    when (code) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_CANCELED,
                        -> onCancelled()   // 用户主动取消：静默，但必须复位状态
                        else -> onFailed(errString.toString())
                    }
                }
            },
        )
        val info = BiometricCapability.buildPromptInfo(
            config = config,
            title = title,
            subtitle = subtitle,
            negativeButtonText = getString(R.string.common_cancel),
        )
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    /** 供自动填充认证界面复用：把解锁后的库暴露给服务。 */
    fun appContainer(): AppContainer = container

    companion object {
        /**
         * 备份文件的 MIME 类型。
         *
         * 用 `application/json` 而不是 `application/octet-stream`：
         * 备份文件本身是自包含 JSON（仅 `payload_enc` 为密文），
         * 而部分文件管理器会按 MIME 猜测/改写扩展名，`octet-stream`
         * 容易让 `.myvault` 后缀被吞掉或变成 `.bin`。
         */
        const val BACKUP_MIME_TYPE = "application/json"

        /**
         * 自动填充服务在「库里没有匹配条目」时带过来的标识。
         *
         * 之所以要传：原生 App 场景下用户根本不知道包名是什么（要翻系统设置），
         * 而这个包名恰恰是唯一可靠的匹配依据。由服务识别、界面预填，
         * 用户只需要补一个看得懂的名字。
         */
        const val EXTRA_AUTOFILL_PACKAGE = "com.myvault.password.extra.AUTOFILL_PACKAGE"

        /** 浏览器场景的域名，预填进「站点」字段。 */
        const val EXTRA_AUTOFILL_WEB_DOMAIN = "com.myvault.password.extra.AUTOFILL_WEB_DOMAIN"
    }
}

/**
 * 应用导航图。
 *
 * 导航被有意设计得「扁平」：没有深层嵌套，也没有隐式路由。
 * 密码库应用不该有复杂的导航状态 —— 每个界面都应当是明确、可预期的。
 */
@Composable
private fun VaultApp(
    activity: MainActivity,
    container: AppContainer,
    biometricMessage: String?,
    pendingImportUri: Uri?,
    onClearImport: () -> Unit,
    onImportPassphrase: (Uri, CharArray) -> Unit,
    onCreateBackupFile: (passphrase: CharArray, isMasterPassword: Boolean) -> Unit,
    onPickBackupFile: () -> Unit,
    onBiometricMessage: (String?) -> Unit,
    autofillPrefill: AutofillPrefill?,
    onConsumeAutofillPrefill: () -> Unit,
) {
    val mainViewModel: MainViewModel = viewModel()
    val mainState by mainViewModel.state.collectAsState()

    // ------------------------------------------------------------ 用户交互上报通道
    //
    // 已解锁界面里有一条**必需的第二条**上报通道，而不是冗余：
    // 导航图根容器上的 `pointerInput` 只覆盖**本 Activity 窗口**里的触摸，
    // 它漏掉了两类真实交互（都曾造成「用户正在操作却被锁定」）：
    //  1. 对话框（口令输入框）在**另一个窗口**里 —— 那里的触摸不经过根容器；
    //  2. 软键盘输入（IME）不产生任何指针事件 —— 提交文字走的是 InputConnection。
    // 因此对话框与文字输入框都要通过 [LocalUserActivity] 显式上报。
    //
    // 这个 `remember` 刻意放在**提前 return 之前**：它是有状态的调用，
    // 一旦落在解锁/锁定不同的组合分支上，就会留下难以推理的状态残留
    // （这也是 [UnlockedVaultNavigation] 被单独抽出来的原因）。
    val reportUserActivity = remember(mainViewModel) {
        { mainViewModel.onUserInteraction() }
    }

    // 前台/后台切换驱动自动锁定计时
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> mainViewModel.onEnterForeground()
                Lifecycle.Event.ON_STOP -> mainViewModel.onEnterBackground()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    var biometricEnrolled by remember { mutableStateOf(false) }
    LaunchedEffect(mainState.lockState) {
        // 判定未完成（Loading）时也按「已锁定」处理：宁可先不显示指纹按钮，
        // 也不要在「其实还没有密码库」时把它显示出来。
        biometricEnrolled = if (mainState.lockState !is LockState.Unlocked) {
            mainViewModel.biometricEnrolled()
        } else {
            false
        }
        // 自动锁定的看门狗由 MainViewModel 在解锁时自行启动，
        // 并且必须在每次用户交互时被重置 —— 见下方 pointerInput。
    }

    // ------------------------------------------------------------ 准入闸门
    //
    // 关键不变量：**未解锁时，密码库的导航图根本不存在**（不参与组合）。
    //
    // 这里曾经只用锁定状态决定 `NavHost` 的 `startDestination`，即「从哪里开始」，
    // 而没有决定「哪些界面可以被渲染」。于是锁定与导航栈成了两个独立的事实来源：
    // 库一旦被锁定，`NavHost` 仍停在原来的路由上（vault / entry / settings …），
    // 锁定并不等于「离开这些界面」—— 锁定状态打开应用仍能进入密码库界面。
    //
    // 现在改为：只有 AppLockGate 放行（明确的 Unlocked）才组合 `NavHost`；
    // 其余状态一律只显示解锁界面，且**不渲染任何密码库界面**。
    // 解锁界面需要的一切（主密码、指纹、创建库）都在分支内自足，
    // 不再依赖导航图里的 `setup` / `lock` 路由。
    when (val gate = AppLockGate.resolve(mainState.lockState)) {
        is AppLockGate.Decision.ShowLockedScreen -> {
            when (gate.screen) {
                AppLockGate.LockedScreen.Setup -> SetupScreen(
                    busy = mainState.busy,
                    errorMessage = mainState.errorMessage,
                    onCreate = mainViewModel::setupVault,
                )
                AppLockGate.LockedScreen.Unlock -> LockScreen(
                    // 判定尚未完成（Loading）：显示不可交互的占位，避免闪现错误的界面
                    busy = mainState.busy || mainState.lockState is LockState.Loading,
                    errorMessage = mainState.errorMessage ?: biometricMessage,
                    biometricEnrolled = biometricEnrolled,
                    biometricReady = mainViewModel.biometricReady(),
                    onUnlock = { password ->
                        onBiometricMessage(null)
                        mainViewModel.unlock(password)
                    },
                    onBiometric = {
                        onBiometricMessage(null)
                        activity.promptBiometricUnlock(
                            onKey = { key -> mainViewModel.unlockWithBiometricKey(key) },
                            onError = { msg -> onBiometricMessage(msg) },
                        )
                    },
                )
            }
            return
        }

        AppLockGate.Decision.EnterVault -> Unit
    }

    // 走到这里才说明库已解锁：密码库导航图**只**在这一支里存在。
    // 交互上报通道只在这一支里提供：解锁界面上的输入不参与自动锁定判定。
    CompositionLocalProvider(LocalUserActivity provides reportUserActivity) {
        UnlockedVaultNavigation(
            activity = activity,
            container = container,
            mainViewModel = mainViewModel,
            mainState = mainState,
            autofillPrefill = autofillPrefill,
            onConsumeAutofillPrefill = onConsumeAutofillPrefill,
            pendingImportUri = pendingImportUri,
            onClearImport = onClearImport,
            onImportPassphrase = onImportPassphrase,
            onCreateBackupFile = onCreateBackupFile,
            onPickBackupFile = onPickBackupFile,
        )
    }
}

/**
 * 已解锁状态下的密码库导航图。
 *
 * 刻意做成独立 composable：它内部有 `rememberNavController` / `viewModel` 等
 * `remember` 调用，必须只在「已解锁」这一支里、且以稳定的调用位置出现，
 * 不能写在带提前 return 的同一个函数体里（否则解锁/锁定切换时，
 * 有状态的调用会落在不同的组合分支上，留下难以推理的状态残留）。
 *
 * 该函数**只会**在 [AppLockGate] 放行后被调用，因此这里不需要、也不应该
 * 再重复判断锁定状态。
 */
@Composable
private fun UnlockedVaultNavigation(
    activity: MainActivity,
    container: AppContainer,
    mainViewModel: MainViewModel,
    mainState: MainUiState,
    autofillPrefill: AutofillPrefill?,
    onConsumeAutofillPrefill: () -> Unit,
    pendingImportUri: Uri?,
    onClearImport: () -> Unit,
    onImportPassphrase: (Uri, CharArray) -> Unit,
    onCreateBackupFile: (passphrase: CharArray, isMasterPassword: Boolean) -> Unit,
    onPickBackupFile: () -> Unit,
) {
    val navController = rememberNavController()

    // 只有走到这里才说明库已解锁，允许渲染密码库导航图。
    // 用户交互采集容器也放在这一支里：解锁界面上的触摸不参与自动锁定判定。
    //
    // 为什么放在容器层而不是每个控件里：任何界面的任何触摸都会经过这个容器，
    // 因此不可能遗漏 —— 遗漏一处就会重现「正在操作却被自动锁定」的缺陷。
    // 这里只记录一个时间戳，不接触任何敏感数据，性能开销可忽略。
    Box(
        modifier = Modifier
            .fillMaxSize()
            .pointerInput(Unit) {
                awaitPointerEventScope {
                    while (true) {
                        awaitPointerEvent()
                        mainViewModel.onUserInteraction()
                    }
                }
            },
    ) {
        NavHost(navController = navController, startDestination = Routes.VAULT) {

        composable(Routes.VAULT) {
            // 自动填充卡片带过来的线索：解锁并进入列表后才消费它，
            // 直接进入「新建条目」并把识别到的包名/域名预填好。
            LaunchedEffect(autofillPrefill) {
                val prefill = autofillPrefill ?: return@LaunchedEffect
                onConsumeAutofillPrefill()
                navController.navigate(
                    Routes.entry(
                        id = null,
                        pkg = prefill.packageName,
                        domain = prefill.webDomain,
                    ),
                )
            }

            VaultListScreen(
                entries = mainState.filteredEntries,
                query = mainState.query,
                message = mainState.message,
                brokenEntryIds = mainState.brokenEntryIds,
                onQueryChange = mainViewModel::setQuery,
                onOpenEntry = { entry -> navController.navigate(Routes.entry(entry.id)) },
                onAddEntry = { navController.navigate(Routes.entry(null)) },
                onToggleFavorite = mainViewModel::toggleFavorite,
                onDeleteEntry = { mainViewModel.deleteEntry(it.id) },
                onCopy = { entry, value, sensitive ->
                    mainViewModel.copyField(entry.id, value, sensitive)
                },
                onCleanupBrokenEntries = mainViewModel::deleteBrokenEntries,
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
                onLock = mainViewModel::lock,
                onMessageShown = mainViewModel::consumeMessage,
            )
        }

        composable(
            route = Routes.ENTRY,
            arguments = listOf(
                navArgument("entryId") {
                    type = NavType.StringType
                    defaultValue = ""
                },
                // 自动填充预填用：包名（原生 App）与域名（浏览器），都为可选
                navArgument("pkg") {
                    type = NavType.StringType
                    defaultValue = ""
                },
                navArgument("domain") {
                    type = NavType.StringType
                    defaultValue = ""
                },
            ),
        ) { backStackEntry ->
            val rawId = backStackEntry.arguments?.getString("entryId").orEmpty()
            val entryId = rawId.ifBlank { null }
            val prefillPackage = backStackEntry.arguments?.getString("pkg").orEmpty().ifBlank { null }
            val prefillDomain = backStackEntry.arguments?.getString("domain").orEmpty().ifBlank { null }
            val editViewModel: EntryEditViewModel = viewModel(
                // 预填内容进 key：否则「上一次用包名 A 建过条目」的 ViewModel
                // 会被复用，界面上显示的还是 A 的包名
                key = "entry-${entryId ?: "new"}-${prefillPackage.orEmpty()}-${prefillDomain.orEmpty()}",
                factory = EntryEditViewModel.factory(entryId, prefillPackage, prefillDomain),
            )
            val state by editViewModel.state.collectAsState()

            LaunchedEffect(state.saved, state.deleted) {
                if (state.saved || state.deleted) navController.popBackStack()
            }

            EntryEditScreen(
                state = state,
                onBack = { navController.popBackStack() },
                onSiteChange = editViewModel::updateSite,
                onUsernameChange = editViewModel::updateUsername,
                onPasswordChange = editViewModel::updatePassword,
                onUrlChange = editViewModel::updateUrl,
                onNotesChange = editViewModel::updateNotes,
                onTogglePasswordVisible = editViewModel::togglePasswordVisible,
                onToggleFavorite = editViewModel::toggleFavorite,
                onRegenerate = editViewModel::regenerate,
                onPolicyChange = editViewModel::updatePolicy,
                onSave = editViewModel::save,
                onDelete = editViewModel::delete,
                onConsumeError = editViewModel::consumeError,
            )
        }

        composable(Routes.GENERATOR) {
            GeneratorScreenHost(
                container = container,
                onBack = { navController.popBackStack() },
                onCopy = { text ->
                    ClipboardHelper.copy(
                        context = activity,
                        label = "MyVault",
                        text = text,
                        sensitive = true,
                        clearAfterMillis = VaultSettingsConstants.DEFAULT_CLIPBOARD_CLEAR_MILLIS,
                    )
                },
            )
        }

        composable(Routes.SETTINGS) {
            val settingsViewModel: SettingsViewModel = viewModel()
            val state by settingsViewModel.state.collectAsState()

            SettingsScreen(
                state = state,
                onBack = { navController.popBackStack() },
                onAutoLockChange = settingsViewModel::setAutoLock,
                onClipboardChange = settingsViewModel::setClipboardClear,
                onBlockScreenshotsChange = settingsViewModel::setBlockScreenshots,
                onImportOverwriteChange = settingsViewModel::setImportOverwrite,
                onLanguageChange = settingsViewModel::setLanguage,
                onOpenChangePassword = settingsViewModel::openChangePassword,
                onCloseChangePassword = settingsViewModel::closeChangePassword,
                onChangeMasterPassword = settingsViewModel::changeMasterPassword,
                onEnableBiometric = { password ->
                    // 第一步：验证口令 + 生成 Keystore 密钥 + 初始化 Cipher
                    settingsViewModel.beginEnableBiometric(password) { cipher ->
                        // 第二步：指纹认证，成功后用同一个 Cipher 包裹数据密钥
                        activity.promptBiometricEnrollWith(
                            cipher = cipher,
                            onAuthenticated = { authed ->
                                settingsViewModel.finishEnableBiometric(authed)
                            },
                            onCancelled = { settingsViewModel.abortEnableBiometric() },
                        )
                    }
                },
                onDisableBiometric = settingsViewModel::disableBiometric,
                onExportBackup = { backupPassphrase, isMasterPassword ->
                    onCreateBackupFile(backupPassphrase, isMasterPassword)
                },
                onImportBackup = onPickBackupFile,
                onOpenAutofillSettings = {
                    runCatching {
                        activity.startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE))
                    }
                },
                onOpenAudit = { navController.navigate(Routes.AUDIT) },
                onOpenOperationLog = { navController.navigate(Routes.OPERATION_LOG) },
                onConsumeMessages = settingsViewModel::consumeMessages,
                // 文件名在进入设置页时生成一次；同一次导出流程中对话框与
                // 实际落盘使用同一个名字，避免「显示的名字」与「写入的名字」不一致。
                suggestedBackupFileName = remember { BackupManager.suggestFileName() },
            )
        }

        composable(Routes.AUDIT) {
            val auditViewModel: AuditViewModel = viewModel()
            val state by auditViewModel.state.collectAsState()

            AuditScreen(
                report = state.report,
                integrity = state.integrity,
                verifying = state.verifying,
                kdfDescription = state.kdfDescription,
                cipherDescription = state.cipherDescription,
                onBack = { navController.popBackStack() },
                onVerify = auditViewModel::verifyIntegrity,
                onCopyReport = {
                    ClipboardHelper.copy(
                        context = activity,
                        label = activity.getString(R.string.audit_report_file_name),
                        text = auditViewModel.rebuildReportText(),
                        sensitive = false,
                        clearAfterMillis = 0,
                    )
                    Toast.makeText(activity, R.string.audit_copied, Toast.LENGTH_SHORT).show()
                },
            )
        }

        composable(Routes.OPERATION_LOG) {
            val logViewModel: OperationLogViewModel = viewModel()
            val state by logViewModel.state.collectAsState()

            OperationLogScreen(
                state = state,
                onBack = { navController.popBackStack() },
            )
        }
    }
    }   // Box（用户交互采集容器）

    // 导入备份：收集备份口令（独立于主密码）
    val importUri = pendingImportUri
    if (importUri != null) {
        PasswordConfirmDialog(
            title = androidx.compose.ui.res.stringResource(R.string.settings_backup_password_title),
            body = androidx.compose.ui.res.stringResource(R.string.settings_backup_password_body),
            requireConfirm = false,
            onDismiss = onClearImport,
            onConfirm = { pwd ->
                onImportPassphrase(importUri, pwd)
                onClearImport()
            },
        )
    }
}

/** 独立的生成器界面宿主（自己维护策略状态）。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GeneratorScreenHost(
    container: AppContainer,
    onBack: () -> Unit,
    onCopy: (String) -> Unit,
) {
    var policy by remember {
        mutableStateOf(PasswordPolicy(length = BuildConfig.DEFAULT_PASSWORD_LENGTH))
    }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    fun regenerate() {
        runCatching { container.passwordGenerator.generate(policy) }
            .onSuccess { password = it; error = null }
            .onFailure { error = it.message }
    }

    LaunchedEffect(Unit) { regenerate() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.gen_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.common_back))
                    }
                },
            )
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner),
        ) {
            GeneratorScreen(
                policy = policy,
                password = password,
                errorMessage = error,
                onPolicyChange = { newPolicy ->
                    policy = newPolicy
                    regenerate()
                },
                onRegenerate = { regenerate() },
                onUse = { text ->
                    onCopy(text)
                    onBack()
                },
                onCopy = onCopy,
            )
        }
    }
}

/**
 * 路由常量：集中定义，避免字符串拼写错误导致运行时导航异常。
 *
 * 注意这里**没有**解锁界面与创建界面的路由。
 * 它们不属于密码库导航图：密码库图只在已解锁时才存在（见 [AppLockGate]），
 * 若把解锁界面做成图内的一条路由，就等于把「未解锁」这种状态也塞进了
 * 只有解锁后才允许存在的容器里 —— 那正是本文件此前的缺陷成因。
 */
private object Routes {
    const val VAULT = "vault"
    const val ENTRY = "entry/{entryId}?pkg={pkg}&domain={domain}"
    const val GENERATOR = "generator"
    const val SETTINGS = "settings"
    const val AUDIT = "audit"
    const val OPERATION_LOG = "operation_log"

    /**
     * 条目路由。
     *
     * @param id 为 null 表示新建
     * @param pkg 自动填充识别到的应用包名（预填进「网址」字段）
     * @param domain 自动填充识别到的域名（预填进「站点」字段）
     */
    fun entry(id: String?, pkg: String? = null, domain: String? = null): String =
        "entry/${id.orEmpty()}?pkg=${Uri.encode(pkg.orEmpty())}&domain=${Uri.encode(domain.orEmpty())}"
}

/** 与 [com.myvault.password.settings.VaultSettings] 默认值保持一致的常量。 */
private object VaultSettingsConstants {
    const val DEFAULT_CLIPBOARD_CLEAR_MILLIS = 30_000L
}
