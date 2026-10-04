package com.myvault.password.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * 用户可见的安全设置。
 *
 * 注意这里存储的**只有策略，不含任何秘密** —— 因此明文放在 DataStore 里
 * 是可以接受的（设备已启用文件级加密）。密钥材料一律不进 DataStore。
 */
data class VaultSettings(
    /** 是否已启用指纹解锁（真实状态以密钥信封里的 bio_dek 为准，这里只是 UI 提示）。 */
    val biometricEnabled: Boolean = DEFAULT_BIOMETRIC_ENABLED,

    /** 自动锁定时长（毫秒）。0 表示「立即」（切到后台就锁）。 */
    val autoLockMillis: Long = DEFAULT_AUTO_LOCK_MILLIS,

    /** 复制密码后多少毫秒清除剪贴板。0 表示不清除（不推荐）。 */
    val clipboardClearMillis: Long = DEFAULT_CLIPBOARD_CLEAR_MILLIS,

    /**
     * 是否禁止截屏与录屏（FLAG_SECURE）。
     *
     * 默认开启。这是真实的安全收益：防止恶意应用通过 MediaProjection
     * 或无障碍服务抓取画面，也防止密码出现在「最近任务」缩略图里。
     * 需要一个可关闭的开关，用于用户自己导出界面截图做验证。
     *
     * 注意：本项目的默认值常量目前是 `true`。进行 adb 取证验证时需要临时
     * 把 [DEFAULT_BLOCK_SCREENSHOTS] 置为 false 并在验证后还原
     * （FLAG_SECURE 生效时 screencap 只能拿到黑屏，这是它应有的行为）。
     */
    val blockScreenshots: Boolean = DEFAULT_BLOCK_SCREENSHOTS,

    /** 导入备份时是否覆盖同 ID 条目。 */
    val importOverwrite: Boolean = DEFAULT_IMPORT_OVERWRITE,

    /** 是否已展示过「自动填充设置指引」。 */
    val autofillHintShown: Boolean = DEFAULT_AUTOFILL_HINT_SHOWN,
) {
    companion object {
        const val DEFAULT_AUTO_LOCK_MILLIS = 60_000L          // 1 分钟
        const val DEFAULT_CLIPBOARD_CLEAR_MILLIS = 30_000L    // 30 秒

        /**
         * 全部设置的**唯一真值来源**。
         * data class 的参数默认值与 DataStore 的键缺失回退值都引用这些常量，
         * 杜绝两处默认值不一致。
         */
        const val DEFAULT_BIOMETRIC_ENABLED = false
        const val DEFAULT_BLOCK_SCREENSHOTS = true
        const val DEFAULT_IMPORT_OVERWRITE = false
        const val DEFAULT_AUTOFILL_HINT_SHOWN = false

        val AUTO_LOCK_OPTIONS = listOf(
            0L,
            30_000L,
            60_000L,
            5 * 60_000L,
            -1L,   // -1 表示从不
        )

        val CLIPBOARD_OPTIONS = listOf(
            15_000L,
            30_000L,
            60_000L,
            0L,    // 0 表示不清除
        )
    }
}

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "vault_settings")

/**
 * 设置的持久化读写。
 *
 * 所有写操作都是「读-改-写」的原子 DataStore 事务；UI 通过 [settings] 流订阅变化，
 * 因此「关闭截屏保护」这类开关会立刻生效，不需要重启应用。
 */
class SettingsStore(private val context: Context) {

    private object Keys {
        val biometricEnabled = booleanPreferencesKey("biometric_enabled")
        val autoLockMillis = intPreferencesKey("auto_lock_millis")   // 注意：-1 用 int 表达「从不」
        val clipboardClearMillis = intPreferencesKey("clipboard_clear_millis")
        val blockScreenshots = booleanPreferencesKey("block_screenshots")
        val importOverwrite = booleanPreferencesKey("import_overwrite")
        val autofillHintShown = booleanPreferencesKey("autofill_hint_shown")
    }

    /**
     * 设置流。
     *
     * 重要：所有「键缺失时的回退值」都必须引用 [VaultSettings] 里声明的默认值，
     * 不能就地再写一个字面量。曾经这里写的是 `prefs[Keys.blockScreenshots] ?: true`，
     * 而 data class 的默认值是另一个值 —— 两处默认值不一致会造成
     * 「改了一处却完全不生效」的疑难故障。现在只有一处真值来源。
     */
    val settings: Flow<VaultSettings> = context.dataStore.data.map { prefs ->
        VaultSettings(
            biometricEnabled = prefs[Keys.biometricEnabled] ?: VaultSettings.DEFAULT_BIOMETRIC_ENABLED,
            autoLockMillis = (prefs[Keys.autoLockMillis]
                ?: VaultSettings.DEFAULT_AUTO_LOCK_MILLIS.toInt()).toLong(),
            clipboardClearMillis = (prefs[Keys.clipboardClearMillis]
                ?: VaultSettings.DEFAULT_CLIPBOARD_CLEAR_MILLIS.toInt()).toLong(),
            blockScreenshots = prefs[Keys.blockScreenshots] ?: VaultSettings.DEFAULT_BLOCK_SCREENSHOTS,
            importOverwrite = prefs[Keys.importOverwrite] ?: VaultSettings.DEFAULT_IMPORT_OVERWRITE,
            autofillHintShown = prefs[Keys.autofillHintShown] ?: VaultSettings.DEFAULT_AUTOFILL_HINT_SHOWN,
        )
    }

    suspend fun current(): VaultSettings = settings.first()

    suspend fun setBiometricEnabled(enabled: Boolean) = edit { it[Keys.biometricEnabled] = enabled }

    suspend fun setAutoLockMillis(millis: Long) = edit { it[Keys.autoLockMillis] = millis.toInt() }

    suspend fun setClipboardClearMillis(millis: Long) = edit { it[Keys.clipboardClearMillis] = millis.toInt() }

    suspend fun setBlockScreenshots(block: Boolean) = edit { it[Keys.blockScreenshots] = block }

    suspend fun setImportOverwrite(overwrite: Boolean) = edit { it[Keys.importOverwrite] = overwrite }

    suspend fun setAutofillHintShown(shown: Boolean) = edit { it[Keys.autofillHintShown] = shown }

    private suspend fun edit(block: (androidx.datastore.preferences.core.MutablePreferences) -> Unit) {
        context.dataStore.edit(block)
    }
}
