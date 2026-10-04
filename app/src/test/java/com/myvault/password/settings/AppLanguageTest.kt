package com.myvault.password.settings

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 界面语言的存档映射。
 *
 * 这一层刻意做成纯 JVM（[AppLanguage] 不引用任何 Android 类），
 * 因此可以在默认测试任务里秒级跑完 —— 语言设置一旦把存档值解析错，
 * 表现是「用户选了英文、重启又变回中文」这种只有真机才会发现的故障。
 */
class AppLanguageTest {

    @Test
    fun `持久化标签与解析必须互逆`() {
        for (language in AppLanguage.entries) {
            assertEquals(
                "标签 ${language.tag} 解析后不是它自己",
                language,
                AppLanguage.fromTag(language.tag),
            )
        }
    }

    @Test
    fun `默认是跟随系统`() {
        assertEquals(AppLanguage.SYSTEM, AppLanguage.DEFAULT)
    }

    @Test
    fun `存档缺失或为空时回退到跟随系统`() {
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag(null))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag(""))
    }

    @Test
    fun `无法识别的存档值回退而不是抛异常`() {
        // 语言只是显示偏好：来自未来版本或被损坏的标签不应让应用启动失败。
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag("ja"))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag("SYSTEM"))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag("zh-CN"))
        assertEquals(AppLanguage.SYSTEM, AppLanguage.fromTag("system "))
    }

    @Test
    fun `标签本身保持稳定`() {
        // 这些值是已落盘的存档格式，改动它们等于让老用户的设置失效。
        assertEquals("system", AppLanguage.SYSTEM.tag)
        assertEquals("zh", AppLanguage.CHINESE.tag)
        assertEquals("en", AppLanguage.ENGLISH.tag)
    }

    @Test
    fun `中文与英文都被支持`() {
        assertEquals(AppLanguage.CHINESE, AppLanguage.fromTag("zh"))
        assertEquals(AppLanguage.ENGLISH, AppLanguage.fromTag("en"))
    }
}
