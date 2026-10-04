package com.myvault.password.core

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import com.myvault.password.settings.AppLanguage

/**
 * 界面语言的实际应用点。
 *
 * ## 为什么需要这个类
 *
 * `values-en/strings.xml` 与 `locales_config.xml` 只解决「翻译存在」，
 * 不解决「用户怎么切换、切换后如何立刻生效」。这两件事必须显式实现。
 *
 * ## 为什么存档用 SharedPreferences 而不是 DataStore
 *
 * 项目里其他设置都走 DataStore（异步）。语言是**唯一**必须在
 * `Application.onCreate` 里同步读到的设置：它在第一个 Activity 组合之前
 * 就必须生效，否则用户会看到一闪而过的错误语言。
 * 用 DataStore 就只能在主线程 `runBlocking`，那正是 `Application` 承诺不做的事
 * （见 [com.myvault.password.VaultApplication] 的注释）。
 * SharedPreferences 的首次读取由框架异步预加载，是这里的正确工具。
 *
 * ## 各 API 级别的行为（已核对 AppCompat 1.7.0 源码）
 *
 * - **API 33+**：`AppCompatDelegate.setApplicationLocales` 直接转发到框架的
 *   `LocaleManager.setApplicationLocales`，由系统持久化并在语言变化时自动重建
 *   Activity。系统「按应用语言」设置页（`ACTION_APP_LOCALE_SETTINGS`）与这里
 *   读写的是**同一份**数据。
 * - **API 32 及以下**：AppCompat 只在进程内保存，**不落盘**，
 *   因此必须在每次启动时由本类重新应用一次；它检测到 Configuration 变化后
 *   会自行 `recreate()` 当前 Activity。
 *
 * 换句话说：本类是语言偏好的**唯一真值来源**，系统/AppCompat 只是执行者。
 * 这样两条路径（应用内切换、系统设置里切换）不会各自记住一半。
 */
object LocaleController {

    private const val PREFS_NAME = "vault_locale"
    private const val KEY_LANGUAGE = "language"

    @Volatile
    private var prefs: android.content.SharedPreferences? = null

    /** 当前选择的语言。读取是纯内存操作，可在组合期直接调用。 */
    fun current(context: Context): AppLanguage {
        val store = store(context)
        return AppLanguage.fromTag(store.getString(KEY_LANGUAGE, null))
    }

    /**
     * 启动时应用已保存的语言。
     *
     * 在 [android.app.Application.onCreate] 里调用：此时还没有任何 Activity，
     * 因此 `setApplicationLocales` 走的是「先设配置、再创建界面」的路径，
     * 不存在重建界面或语言闪烁的问题。
     */
    fun applyStored(context: Context) {
        apply(current(context))
    }

    /**
     * 切换语言：落盘 + 立即生效。
     *
     * 生效方式不需要调用方干预 —— AppCompat 检测到 Configuration 变化后
     * 会自行重建 Activity（本应用的 `configChanges` 没有声明 `locale`，
     * 因此重建路径是通的）。
     */
    fun setLanguage(context: Context, language: AppLanguage) {
        store(context).edit().putString(KEY_LANGUAGE, language.tag).apply()
        apply(language)
    }

    private fun apply(language: AppLanguage) {
        // 空列表 = 交还给系统语言。这正是「跟随系统」的语义。
        val locales = when (language) {
            AppLanguage.SYSTEM -> LocaleListCompat.getEmptyLocaleList()
            AppLanguage.CHINESE -> LocaleListCompat.forLanguageTags("zh")
            AppLanguage.ENGLISH -> LocaleListCompat.forLanguageTags("en")
        }
        AppCompatDelegate.setApplicationLocales(locales)
    }

    private fun store(context: Context): android.content.SharedPreferences =
        prefs ?: synchronized(this) {
            prefs ?: context.applicationContext
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .also { prefs = it }
        }
}
