package com.myvault.password.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 「改过密码后保存要二次确认」这条规则的回归测试（纯 JVM，不依赖 Android）。
 *
 * 为什么值得单独钉住：这条判定决定的是**界面会不会多拦一次**，
 * 两个方向判错都有代价 ——
 *
 *  - 判得太宽（例如「中途改过就永远要确认」）：每次改完再改回原值、甚至只是
 *    重新生成一次相同强度的密码，都会被弹一次确认框；用户很快养成
 *    「无脑点确定」的习惯，正好抵消掉真正该拦的那一次；
 *  - 判得太窄（例如对大小写 / 空格做归一）：用户把一个字符改掉后认为
 *    「反正没变」，保存却静默覆盖了旧密码 —— 旧密码在本应用里不可恢复。
 */
class EntryEditRulesTest {

    @Test
    fun `新建条目即使填了密码也不二次确认`() {
        // 新建没有「原来的密码」可覆盖：确认只会变成每次新建都要多点一下的噪音
        assertFalse(
            EntryEditRules.passwordChangedDuringEdit(
                isNew = true,
                originalPassword = null,
                currentPassword = "brand-new",
            ),
        )
    }

    @Test
    fun `已有条目未改密码时不二次确认`() {
        // 只改了站点名称或备注就保存 —— 这是最常见的一次编辑，不该被打断
        assertFalse(
            EntryEditRules.passwordChangedDuringEdit(
                isNew = false,
                originalPassword = "s3cret-pass",
                currentPassword = "s3cret-pass",
            ),
        )
    }

    @Test
    fun `已有条目改了密码就要二次确认`() {
        assertTrue(
            EntryEditRules.passwordChangedDuringEdit(
                isNew = false,
                originalPassword = "old-pass",
                currentPassword = "new-pass",
            ),
        )
    }

    @Test
    fun `只差一个字符也算改动`() {
        // 极易漏判的一类：用户以为「只是多敲了一个字符」
        assertTrue(
            EntryEditRules.passwordChangedDuringEdit(
                isNew = false,
                originalPassword = "Passw0rd",
                currentPassword = "Passw0rd1",
            ),
        )
    }

    @Test
    fun `首尾空格与大小写不做归一`() {
        // 密码里的空格与大小写都是有意义的字符；做 trim / 小写归一
        // 会让这两种真实改动逃过确认
        assertTrue(
            EntryEditRules.passwordChangedDuringEdit(
                isNew = false,
                originalPassword = "Passw0rd",
                currentPassword = "Passw0rd ",
            ),
        )
        assertTrue(
            EntryEditRules.passwordChangedDuringEdit(
                isNew = false,
                originalPassword = "Passw0rd",
                currentPassword = "passw0rd",
            ),
        )
    }

    @Test
    fun `改了又改回原值就不需要确认`() {
        // 判定只看最终值，不记「中途改过」：改了再改回等于没改
        val original = "same-pass"
        assertFalse(
            EntryEditRules.passwordChangedDuringEdit(
                isNew = false,
                originalPassword = original,
                currentPassword = original,
            ),
        )
    }

    @Test
    fun `条目读不出来时不做不可判定的拦截`() {
        // 条目损坏 / 读不到时没有「原密码」可比。此时无法区分
        // 「用户改了密码」与「用户第一次补密码」，因此不弹一个说不清缘由的确认框
        assertFalse(
            EntryEditRules.passwordChangedDuringEdit(
                isNew = false,
                originalPassword = null,
                currentPassword = "anything",
            ),
        )
    }
}
