package com.myvault.password.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockClock
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.annotation.StringRes
import com.myvault.password.BuildConfig
import com.myvault.password.R
import com.myvault.password.settings.AppLanguage
import com.myvault.password.settings.VaultSettings
import com.myvault.password.ui.SettingsState
import com.myvault.password.ui.components.LanguageChoiceRow
import com.myvault.password.ui.components.LocalUserActivity
import com.myvault.password.ui.components.WarningCard
import com.myvault.password.ui.components.reportsUserActivity

/**
 * 设置界面。
 *
 * 每一项都配有一句「这到底是干什么的」说明，而不是只给一个开关。
 * 安全设置的默认值必须是安全的，用户改动时应当理解自己在放弃什么。
 *
 * 三个需要重新输入主密码的动作（改密码 / 开启指纹 / 关闭指纹）都会弹出
 * 口令输入框 —— 已经解锁的会话不能成为绕过强认证的后门。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    state: SettingsState,
    onBack: () -> Unit,
    onAutoLockChange: (Long) -> Unit,
    onClipboardChange: (Long) -> Unit,
    onBlockScreenshotsChange: (Boolean) -> Unit,
    onImportOverwriteChange: (Boolean) -> Unit,
    /** 切换界面语言。调用方负责落盘并触发 Configuration 变化。 */
    onLanguageChange: (AppLanguage) -> Unit,
    onOpenChangePassword: () -> Unit,
    onCloseChangePassword: () -> Unit,
    onChangeMasterPassword: (CharArray, CharArray) -> Unit,
    onEnableBiometric: (CharArray) -> Unit,
    onDisableBiometric: (CharArray) -> Unit,
    /**
     * 导出备份。
     *
     * @param passphrase 备份文件自身的加密口令
     * @param isMasterPassword 该口令是否「就是主密码」。
     *   为 true 时调用方会先向密钥库校验它 —— 打错主密码会让备份文件
     *   用一个错误口令加密，等到需要恢复时才发现打不开就太晚了。
     */
    onExportBackup: (passphrase: CharArray, isMasterPassword: Boolean) -> Unit,
    onImportBackup: () -> Unit,
    /** 打开扫码导入（相机 / 图片识别 → 预览 → 写入密码库）。 */
    onOpenQrImport: () -> Unit,
    onOpenAutofillSettings: () -> Unit,
    onOpenAudit: () -> Unit,
    /** 打开操作日志（最近 30 天的删除、改密、改名与备份记录）。 */
    onOpenOperationLog: () -> Unit,
    onConsumeMessages: () -> Unit,
    /** 导出时建议的文件名（由调用方用 BackupManager 生成，便于与真实落盘名一致）。 */
    suggestedBackupFileName: String,
) {
    val snackbarHostState = remember { SnackbarHostState() }

    // 需要口令确认的对话框状态
    var passwordFor by remember { mutableStateOf<PasswordPurpose?>(null) }
    var exportDialogOpen by remember { mutableStateOf(false) }

    LaunchedEffect(state.message, state.error) {
        val text = state.message ?: state.error
        if (text != null) {
            snackbarHostState.showSnackbar(text)
            onConsumeMessages()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    navigationIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    actionIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.common_back))
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .verticalScroll(rememberScrollState()),
        ) {
            // ================================================== 安全
            SectionHeader(stringResource(R.string.settings_security))

            SettingsRow(
                icon = Icons.Default.Lock,
                title = stringResource(R.string.settings_change_password),
                subtitle = state.kdfDescription.ifBlank { null },
                onClick = onOpenChangePassword,
            )

            SettingsSwitchRow(
                icon = Icons.Default.Fingerprint,
                title = stringResource(R.string.settings_biometric),
                subtitle = when {
                    !state.biometricReady -> stringResource(R.string.settings_biometric_unavailable)
                    state.biometricEnabled -> stringResource(R.string.settings_biometric_summary_on)
                    else -> stringResource(R.string.settings_biometric_summary_off)
                },
                checked = state.biometricEnabled,
                enabled = state.biometricReady && !state.working,
                // 进行中显示进度而不是开关：把「正在校验并通过 Argon2id 重新封装密钥」
                // 这件事明确告诉用户。这一段耗时不可压缩（见 SettingsViewModel 的说明），
                // 因此必须给出反馈，否则就表现为「点了没反应」。
                inProgress = state.working,
                onCheckedChange = { want ->
                    passwordFor = if (want) PasswordPurpose.ENABLE_BIOMETRIC else PasswordPurpose.DISABLE_BIOMETRIC
                },
            )

            ChoiceRow(
                icon = Icons.Default.LockClock,
                title = stringResource(R.string.settings_auto_lock),
                current = autoLockLabel(state.autoLockMillis),
                options = VaultSettings.AUTO_LOCK_OPTIONS.map { autoLockLabel(it) to it },
                onSelected = onAutoLockChange,
            )
            ChoiceRow(
                icon = Icons.Default.ContentCopy,
                title = stringResource(R.string.settings_clipboard_clear),
                current = clipboardLabel(state.clipboardClearMillis),
                options = VaultSettings.CLIPBOARD_OPTIONS.map { clipboardLabel(it) to it },
                onSelected = onClipboardChange,
            )

            SettingsSwitchRow(
                icon = Icons.Default.Shield,
                title = stringResource(R.string.settings_screenshot_block),
                subtitle = stringResource(R.string.settings_screenshot_block_summary),
                checked = state.blockScreenshots,
                enabled = true,
                onCheckedChange = onBlockScreenshotsChange,
            )

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            // ================================================== 自动填充
            SectionHeader(stringResource(R.string.settings_autofill))
            SettingsRow(
                icon = Icons.Default.Password,
                title = stringResource(R.string.settings_autofill),
                subtitle = stringResource(R.string.settings_autofill_howto),
                onClick = onOpenAutofillSettings,
            )

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            // ================================================== 界面语言
            // 单独成节，而不是塞进「安全」：语言是显示偏好，与安全策略无关，
            // 混在一起会让用户以为改语言会影响加密行为。
            SectionHeader(stringResource(R.string.settings_language))

            LanguageChoiceRow(
                current = state.language,
                onSelect = onLanguageChange,
            )
            Text(
                text = stringResource(R.string.settings_language_summary),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 2.dp),
            )

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            // ================================================== 备份
            SectionHeader(stringResource(R.string.settings_backup))
            Spacer(Modifier.height(4.dp))
            WarningCard(
                title = stringResource(R.string.settings_backup_password_title),
                body = stringResource(R.string.settings_backup_warning),
            )
            Spacer(Modifier.height(10.dp))
            SettingsRow(
                icon = Icons.Default.FileDownload,
                title = stringResource(R.string.settings_export),
                subtitle = stringResource(R.string.settings_export_summary),
                onClick = { exportDialogOpen = true },
            )
            SettingsRow(
                icon = Icons.Default.FileUpload,
                title = stringResource(R.string.settings_import),
                subtitle = stringResource(R.string.settings_import_summary),
                onClick = onImportBackup,
            )
            SettingsRow(
                icon = Icons.Default.QrCodeScanner,
                title = stringResource(R.string.qr_import_entry),
                subtitle = stringResource(R.string.qr_import_entry_summary),
                onClick = onOpenQrImport,
            )
            SettingsSwitchRow(
                icon = Icons.Default.FileUpload,
                title = stringResource(R.string.settings_import_replace),
                subtitle = stringResource(R.string.settings_import_replace_summary),
                checked = state.importOverwrite,
                enabled = true,
                onCheckedChange = onImportOverwriteChange,
            )

            HorizontalDivider(Modifier.padding(vertical = 8.dp))

            // ================================================== 自证与关于
            SectionHeader(stringResource(R.string.settings_audit))
            SettingsRow(
                icon = Icons.Default.Shield,
                title = stringResource(R.string.settings_audit),
                subtitle = stringResource(R.string.settings_audit_summary),
                onClick = onOpenAudit,
            )
            SettingsRow(
                icon = Icons.Default.History,
                title = stringResource(R.string.settings_operation_log),
                subtitle = stringResource(R.string.settings_operation_log_summary),
                onClick = onOpenOperationLog,
            )
            SettingsRow(
                icon = Icons.Default.Key,
                title = stringResource(R.string.settings_about),
                subtitle = stringResource(
                    R.string.settings_about_summary,
                    BuildConfig.VERSION_NAME,
                    state.entryCount,
                    state.keyId,
                ),
                onClick = null,
            )

            Spacer(Modifier.height(32.dp))
        }
    }

    // ------------------------------------------------------ 修改主密码
    if (state.changingPassword) {
        ChangePasswordDialog(
            working = state.working,
            error = state.error,
            onDismiss = onCloseChangePassword,
            onConfirm = onChangeMasterPassword,
        )
    }

    // ------------------------------------------------------ 导出备份：设置备份口令
    if (exportDialogOpen) {
        BackupPassphraseDialog(
            suggestedFileName = suggestedBackupFileName,
            entryCount = state.entryCount,
            onDismiss = { exportDialogOpen = false },
            onConfirm = { passphrase, isMasterPassword ->
                exportDialogOpen = false
                onExportBackup(passphrase, isMasterPassword)
            },
        )
    }

    // ------------------------------------------------------ 单一用途的口令确认框
    val purpose = passwordFor
    if (purpose != null) {
        PasswordConfirmDialog(
            title = stringResource(purpose.titleRes),
            body = stringResource(purpose.bodyRes),
            requireConfirm = false,
            onDismiss = { passwordFor = null },
            onConfirm = { pwd ->
                passwordFor = null
                when (purpose) {
                    PasswordPurpose.ENABLE_BIOMETRIC -> onEnableBiometric(pwd)
                    PasswordPurpose.DISABLE_BIOMETRIC -> onDisableBiometric(pwd)
                }
            },
        )
    }
}

/**
 * 需要口令确认的动作。
 *
 * 存放的是**资源 id** 而不是译文：这样即使语言在对话框打开期间被切换
 * （Activity 会重建，但对话框状态可能被 remember 保留），
 * 文案也总是按当前语言重新解析，不会残留旧语言。
 */
private enum class PasswordPurpose(
    @StringRes val titleRes: Int,
    @StringRes val bodyRes: Int,
) {
    ENABLE_BIOMETRIC(
        R.string.settings_biometric_enable_title,
        R.string.settings_biometric_enable_body,
    ),
    DISABLE_BIOMETRIC(
        R.string.settings_biometric_disable_title,
        R.string.settings_biometric_disable_body,
    ),
}

// ============================================================ 基础组件

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp),
    )
}

@Composable
private fun SettingsRow(
    icon: ImageVector,
    title: String,
    subtitle: String?,
    onClick: (() -> Unit)?,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(22.dp),
        )
        Column(Modifier.padding(start = 14.dp)) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge)
            if (!subtitle.isNullOrBlank()) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
    }
}

@Composable
private fun SettingsSwitchRow(
    icon: ImageVector,
    title: String,
    subtitle: String?,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    /** 进行中：用进度圈替换开关，并显示「进行中」文案，让用户知道操作已被接受。 */
    inProgress: Boolean = false,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(22.dp),
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 14.dp),
        ) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge)
            val subtitleText = if (inProgress) {
                stringResource(R.string.settings_biometric_working)
            } else {
                subtitle
            }
            if (!subtitleText.isNullOrBlank()) {
                Text(
                    text = subtitleText,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (inProgress) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
        if (inProgress) {
            CircularProgressIndicator(
                modifier = Modifier.size(24.dp),
                strokeWidth = 2.dp,
            )
        } else {
            Switch(checked = checked, onCheckedChange = onCheckedChange, enabled = enabled)
        }
    }
}

/** 单选列表行：点击弹出选项对话框。 */
@Composable
private fun <T> ChoiceRow(
    icon: ImageVector,
    title: String,
    current: String,
    options: List<Pair<String, T>>,
    onSelected: (T) -> Unit,
) {
    var open by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { open = true }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(22.dp),
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 14.dp),
        ) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = current,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
    }

    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            title = { Text(title) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    options.forEach { (label, value) ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    onSelected(value)
                                    open = false
                                }
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = label == current, onClick = {
                                onSelected(value)
                                open = false
                            })
                            Text(label, modifier = Modifier.padding(start = 4.dp))
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { open = false }) { Text(stringResource(R.string.common_cancel)) }
            },
        )
    }
}

// ============================================================ 对话框

@Composable
private fun ChangePasswordDialog(
    working: Boolean,
    error: String?,
    onDismiss: () -> Unit,
    onConfirm: (CharArray, CharArray) -> Unit,
) {
    var current by remember { mutableStateOf("") }
    var newPassword by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }

    // 对话框在**独立窗口**里，且这里有三个口令字段（当前 / 新 / 确认）：
    // 输入时间很容易超过闲置超时，必须逐字符上报（详见 LocalUserActivity）。
    val reportUserActivity = LocalUserActivity.current

    val mismatch = confirm.isNotEmpty() && confirm != newPassword
    val tooShort = newPassword.isNotEmpty() && newPassword.length < MIN_MASTER_LENGTH
    val canSubmit = current.isNotEmpty() && newPassword.length >= MIN_MASTER_LENGTH &&
        confirm == newPassword && !working

    AlertDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = { Text(stringResource(R.string.settings_change_password_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()).reportsUserActivity()) {
                OutlinedTextField(
                    value = current,
                    onValueChange = { reportUserActivity(); current = it },
                    label = { Text(stringResource(R.string.settings_current_password)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = if (visible) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Next,
                    ),
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = newPassword,
                    onValueChange = { reportUserActivity(); newPassword = it },
                    label = { Text(stringResource(R.string.settings_new_password)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    isError = tooShort,
                    visualTransformation = if (visible) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Next,
                    ),
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { reportUserActivity(); confirm = it },
                    label = { Text(stringResource(R.string.settings_confirm_new_password)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    isError = mismatch,
                    visualTransformation = if (visible) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    supportingText = {
                        when {
                            tooShort -> Text(stringResource(R.string.setup_too_short))
                            mismatch -> Text(stringResource(R.string.setup_mismatch))
                        }
                    },
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = { visible = !visible }) {
                        Icon(
                            imageVector = if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = null,
                        )
                        Text(
                            text = stringResource(
                                if (visible) R.string.unlock_hide_password else R.string.unlock_show_password,
                            ),
                            modifier = Modifier.padding(start = 6.dp),
                        )
                    }
                }
                if (error != null) {
                    Text(
                        text = error,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Text(
                    text = stringResource(R.string.settings_change_password_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(current.toCharArray(), newPassword.toCharArray()) },
                enabled = canSubmit,
            ) {
                if (working) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.settings_change_password_action))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !working) {
                Text(stringResource(R.string.common_cancel))
            }
        },
    )
}

/** 通用口令确认对话框（用于开启/关闭指纹、导出备份）。 */
@Composable
fun PasswordConfirmDialog(
    title: String,
    body: String,
    requireConfirm: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (CharArray) -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }

    // 对话框是**独立窗口**：它的触摸不会经过已解锁界面根容器上的 pointerInput，
    // 而软键盘输入更不产生指针事件。因此这里必须显式上报（详见 LocalUserActivity）。
    val reportUserActivity = LocalUserActivity.current

    val mismatch = requireConfirm && confirm.isNotEmpty() && confirm != password
    val canSubmit = password.isNotEmpty() && (!requireConfirm || confirm == password)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()).reportsUserActivity()) {
                Text(
                    text = body,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { reportUserActivity(); password = it },
                    label = { Text(stringResource(R.string.unlock_master_password)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = if (visible) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = if (requireConfirm) ImeAction.Next else ImeAction.Done,
                    ),
                )
                if (requireConfirm) {
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = confirm,
                        onValueChange = { reportUserActivity(); confirm = it },
                        label = { Text(stringResource(R.string.settings_confirm_new_password)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        isError = mismatch,
                        visualTransformation = if (visible) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        supportingText = {
                            if (mismatch) Text(stringResource(R.string.setup_mismatch))
                        },
                    )
                }
                TextButton(onClick = { visible = !visible }) {
                    Icon(
                        imageVector = if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = null,
                    )
                    Text(
                        text = stringResource(
                            if (visible) R.string.unlock_hide_password else R.string.unlock_show_password,
                        ),
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(if (requireConfirm) password.toCharArray() else password.toCharArray()) },
                enabled = canSubmit,
            ) {
                Text(stringResource(R.string.common_ok))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) }
        },
    )
}

/**
 * 备份口令对话框。
 *
 * 设计要点（两个曾经的缺陷都源于这里的语义不清）：
 *
 *  1. **「复用主密码」是一个选择，不是一个按钮**。早先它被做成对话框底部的
 *     一个文字按钮，回调里只有 `exportDialogOpen = false` —— 点了等于什么都没做，
 *     用户看到的就是「页面直接关闭了」。现在用二选一的形式表达：
 *     「用独立口令」或「复用主密码」，两者都能真正完成导出。
 *
 *  2. **按钮可用性必须与提示文字一致**。早先提示写着「可以留空以复用主密码」，
 *     但按钮要求 `length >= 8`，于是留空时按钮是灰的 —— 提示在撒谎。
 *     现在选择「复用主密码」时口令字段收起，按钮恒可用；
 *     选择「独立口令」时必须填够长度且两次一致，按钮才可用。
 *
 * 同时**明确展示将要生成的文件名与保存位置的处理方式**：
 * 用户在此之前看不到任何关于「文件叫什么、存在哪」的信息，
 * 而备份文件一旦放下就可能几年不动 —— 这是他最需要知道的。
 */
@Composable
fun BackupPassphraseDialog(
    suggestedFileName: String,
    /** 当前库内条目数。用于让用户明确知道这份备份里到底有什么。 */
    entryCount: Int,
    onDismiss: () -> Unit,
    onConfirm: (passphrase: CharArray, isMasterPassword: Boolean) -> Unit,
) {
    /** 口令来源：独立口令（默认，更安全）或直接复用主密码。 */
    var useOwnPassphrase by remember { mutableStateOf(true) }
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var masterPassword by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }

    // 导出对话框是**独立窗口**，且这里的口令往往要输入两遍（12 个字符以上）：
    // 若不计入用户交互，用户在输入备份口令时就会撞上闲置超时被锁定，
    // 对话框连同整个导出流程一起消失。因此每个字符都上报一次（详见 LocalUserActivity）。
    val reportUserActivity = LocalUserActivity.current

    val mismatch = confirm.isNotEmpty() && confirm != passphrase
    val ownTooShort = passphrase.isNotEmpty() && passphrase.length < MIN_MASTER_LENGTH
    val ownReady = passphrase.length >= MIN_MASTER_LENGTH && confirm == passphrase
    val masterReady = masterPassword.isNotEmpty()
    val canSubmit = if (useOwnPassphrase) ownReady else masterReady

    /**
     * 为什么按钮不可用 —— 必须把原因写出来。
     *
     * 一个「莫名其妙置灰」的按钮只会让用户困惑；告诉他还差什么，他就能自己解决。
     * 这类「禁用但不解释」是移动端最常见的可用性缺陷之一。
     */
    val disabledReason: String? = when {
        useOwnPassphrase && passphrase.isEmpty() ->
            stringResource(R.string.settings_backup_need_passphrase)
        useOwnPassphrase && passphrase.length < MIN_MASTER_LENGTH ->
            stringResource(R.string.settings_backup_passphrase_too_short, MIN_MASTER_LENGTH)
        useOwnPassphrase && confirm != passphrase ->
            stringResource(R.string.settings_backup_confirm_missing)
        !useOwnPassphrase && masterPassword.isEmpty() ->
            stringResource(R.string.settings_backup_need_master)
        else -> null
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.settings_backup_password_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()).reportsUserActivity()) {
                // ---- 这份备份里有什么 ----
                // 明确写出条目数：用户据此判断「现在导出是否有意义」。
                // 空库导出得到的是一个合法但没有凭据的文件 —— 必须让他事先知道。
                Surface(
                    color = if (entryCount == 0) {
                        MaterialTheme.colorScheme.errorContainer
                    } else {
                        MaterialTheme.colorScheme.secondaryContainer
                    },
                    shape = MaterialTheme.shapes.medium,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(Modifier.padding(12.dp)) {
                        val onContainer = if (entryCount == 0) {
                            MaterialTheme.colorScheme.onErrorContainer
                        } else {
                            MaterialTheme.colorScheme.onSecondaryContainer
                        }
                        Text(
                            text = if (entryCount == 0) {
                                stringResource(R.string.settings_backup_empty_title)
                            } else {
                                stringResource(R.string.settings_backup_content_title, entryCount)
                            },
                            style = MaterialTheme.typography.titleSmall,
                            color = onContainer,
                        )
                        Text(
                            text = if (entryCount == 0) {
                                stringResource(R.string.settings_backup_empty_body)
                            } else {
                                stringResource(R.string.settings_export_filename_label)
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = onContainer,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                        Text(
                            text = suggestedFileName,
                            style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace,
                            color = onContainer,
                        )
                        Text(
                            text = stringResource(R.string.settings_export_location_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = onContainer,
                            modifier = Modifier.padding(top = 6.dp),
                        )
                        // 单独一行、用次级样式强调「没有网络位置时怎么办」：
                        // 这是用户实际会遇到的卡点（系统选择器默认只有本机存储）。
                        Text(
                            text = stringResource(R.string.settings_export_location_detail),
                            style = MaterialTheme.typography.bodySmall,
                            color = onContainer,
                            modifier = Modifier.padding(top = 6.dp),
                        )
                    }
                }

                Spacer(Modifier.height(14.dp))

                // ---- 口令来源：二选一 ----
                Text(
                    text = stringResource(R.string.settings_backup_passphrase_source),
                    style = MaterialTheme.typography.labelLarge,
                )
                Spacer(Modifier.height(4.dp))

                ChoiceOption(
                    selected = useOwnPassphrase,
                    title = stringResource(R.string.settings_backup_use_own),
                    detail = stringResource(R.string.settings_backup_use_own_detail),
                    onSelect = { useOwnPassphrase = true },
                )
                ChoiceOption(
                    selected = !useOwnPassphrase,
                    title = stringResource(R.string.settings_backup_use_master),
                    detail = stringResource(R.string.settings_backup_use_master_detail),
                    onSelect = { useOwnPassphrase = false },
                )

                Spacer(Modifier.height(10.dp))

                if (useOwnPassphrase) {
                    OutlinedTextField(
                        value = passphrase,
                        onValueChange = { reportUserActivity(); passphrase = it },
                        label = { Text(stringResource(R.string.settings_backup_password)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        isError = ownTooShort,
                        visualTransformation = if (visible) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Next,
                        ),
                    )
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = confirm,
                        onValueChange = { reportUserActivity(); confirm = it },
                        label = { Text(stringResource(R.string.settings_backup_confirm)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        isError = mismatch,
                        visualTransformation = if (visible) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        supportingText = {
                            Text(
                                stringResource(
                                    R.string.settings_backup_password_min_hint,
                                    MIN_MASTER_LENGTH,
                                ),
                            )
                        },
                    )
                } else {
                    // 复用主密码：这里**必须**校验主密码 ——
                    // 备份文件是用它重新加密整份数据的。
                    OutlinedTextField(
                        value = masterPassword,
                        onValueChange = { reportUserActivity(); masterPassword = it },
                        label = { Text(stringResource(R.string.settings_master_password_for_backup)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        visualTransformation = if (visible) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation()
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done,
                        ),
                        supportingText = {
                            Text(stringResource(R.string.settings_backup_master_verify_hint))
                        },
                    )
                }

                TextButton(onClick = { visible = !visible }) {
                    Icon(
                        imageVector = if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = null,
                    )
                    Text(
                        text = stringResource(
                            if (visible) R.string.unlock_hide_password else R.string.unlock_show_password,
                        ),
                        modifier = Modifier.padding(start = 6.dp),
                    )
                }

                // 按钮为何不可用 —— 直接写在按钮上方
                if (disabledReason != null) {
                    Text(
                        text = disabledReason,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onConfirm(
                        (if (useOwnPassphrase) passphrase else masterPassword).toCharArray(),
                        !useOwnPassphrase,
                    )
                },
                enabled = canSubmit,
            ) {
                // 按钮文案明确指出「下一步是选择保存位置」，
                // 而不是含糊的「确定」——用户需要知道接下来会发生什么。
                Text(stringResource(R.string.settings_export_action))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) }
        },
    )
}

/** 单选行：用于「口令来源」这类二选一。 */
@Composable
private fun ChoiceOption(
    selected: Boolean,
    title: String,
    detail: String,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onSelect)
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(selected = selected, onClick = onSelect)
        Column(Modifier.padding(start = 4.dp)) {
            Text(text = title, style = MaterialTheme.typography.bodyMedium)
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
    }
}

// ============================================================ 标签

@Composable
private fun autoLockLabel(millis: Long): String = when {    millis < 0 -> stringResource(R.string.settings_auto_lock_never)
    millis == 0L -> stringResource(R.string.settings_auto_lock_immediately)
    millis <= 30_000L -> stringResource(R.string.settings_auto_lock_30s)
    millis <= 60_000L -> stringResource(R.string.settings_auto_lock_1m)
    else -> stringResource(R.string.settings_auto_lock_5m)
}

@Composable
private fun clipboardLabel(millis: Long): String = when {
    millis <= 0L -> stringResource(R.string.settings_clipboard_off)
    else -> stringResource(R.string.settings_clipboard_seconds, (millis / 1000).toInt())
}
