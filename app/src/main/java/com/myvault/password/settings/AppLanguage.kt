package com.myvault.password.settings

/**
 * 界面语言。
 *
 * 这个枚举刻意**不依赖任何 Android 类**：语言标签与解析逻辑放在纯 JVM 里，
 * 因此可以用最快的单元测试覆盖「存档值 → 语言」这一层映射
 * （包括存档里出现无法识别的值时如何回退）。
 *
 * 真正的应用方式（AppCompatDelegate / 系统 per-app locale）在
 * [com.myvault.password.core.LocaleController] 里，那里才需要 Android 类。
 */
enum class AppLanguage(
    /** 持久化用的标签。改动它等于改动存档格式，必须保留旧值可读。 */
    val tag: String,
) {
    /** 跟随系统。这是默认值 —— 首次安装不改变用户任何既有习惯。 */
    SYSTEM("system"),

    CHINESE("zh"),

    ENGLISH("en"),
    ;

    companion object {
        val DEFAULT = SYSTEM

        /**
         * 把存档值解析成语言，无法识别时回退到 [DEFAULT]。
         *
         * 这里**不抛异常**：语言只是显示偏好，一个损坏或来自未来版本的标签
         * 不应该让应用启动失败。
         */
        fun fromTag(tag: String?): AppLanguage =
            entries.firstOrNull { it.tag == tag } ?: DEFAULT
    }
}
