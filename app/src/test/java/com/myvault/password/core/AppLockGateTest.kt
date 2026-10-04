package com.myvault.password.core

import com.myvault.password.ui.LockState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 准入闸门测试 —— 钉住密码库最关键的一条界面不变量：
 *
 * > **未解锁时，密码库界面（导航图）不可能被渲染。**
 *
 * 背景：这里曾出现过一个真实缺陷 —— 锁定状态只被用来决定 `NavHost` 的
 * 初始路由（`startDestination`），即「从哪里开始」，却没有决定
 * 「哪些界面允许被渲染」。于是锁定与导航栈成为两个独立的事实来源：
 * 库被锁定后 `NavHost` 仍停在原路由上，锁定状态打开应用仍能进入密码库界面。
 *
 * 判定方式刻意做成**白名单**：只有明确的 [LockState.Unlocked] 才算放行。
 * 因此将来若新增某种锁定状态，默认结果必然是「留在解锁界面」——
 * 这个测试会把「不小心让它进了密码库」当场抓住。
 */
class AppLockGateTest {

    /** 枚举当前全部状态（含 Loading）。新增状态时请一并加入。 */
    private val allStates = listOf(
        LockState.Loading,
        LockState.NeedsSetup,
        LockState.Locked,
        LockState.Unlocked("key-under-test"),
    )

    /** 该状态下是否允许渲染密码库界面。 */
    private fun allowsVault(state: LockState): Boolean = AppLockGate.resolve(state).isUnlocked

    // ------------------------------------------------------------ 白名单不变量

    @Test
    fun `只有已解锁状态才允许渲染密码库界面`() {
        for (state in allStates) {
            val expected = state is LockState.Unlocked
            assertEquals(
                "状态 $state 是否允许渲染密码库界面",
                expected,
                allowsVault(state),
            )
        }
    }

    @Test
    fun `任何未解锁状态都映射到一个解锁界面`() {
        for (state in allStates) {
            val decision = AppLockGate.resolve(state)
            if (state is LockState.Unlocked) {
                assertTrue("已解锁状态不应被拦下", decision is AppLockGate.Decision.EnterVault)
            } else {
                assertTrue(
                    "未解锁状态 $state 必须只显示解锁界面，实际为 $decision",
                    decision is AppLockGate.Decision.ShowLockedScreen,
                )
            }
        }
    }

    // ------------------------------------------------------------ 逐状态语义

    @Test
    fun `已创建但未解锁时只显示解锁界面`() {
        val decision = AppLockGate.resolve(LockState.Locked)
        assertEquals(
            AppLockGate.Decision.ShowLockedScreen(AppLockGate.LockedScreen.Unlock),
            decision,
        )
        assertFalse(decision.isUnlocked)
    }

    @Test
    fun `尚无密码库时只显示创建界面`() {
        // 创建流程会生成一份全新的密码库，因此它同样必须独占界面 ——
        // 既不能让用户看到既有内容，也不能让创建流程与密码库界面并存。
        val decision = AppLockGate.resolve(LockState.NeedsSetup)
        assertEquals(
            AppLockGate.Decision.ShowLockedScreen(AppLockGate.LockedScreen.Setup),
            decision,
        )
        assertFalse(decision.isUnlocked)
    }

    @Test
    fun `判定未完成时显示不可进入的解锁界面`() {
        // Loading 是启动瞬间的状态：此时既不知道有没有库、也不知道解锁与否。
        // 绝不能把它当作已解锁（那会让密码库界面在判定完成前闪现），
        // 也不能显示创建界面（那会诱导用户在已有库的设备上走创建流程）。
        val decision = AppLockGate.resolve(LockState.Loading)
        assertEquals(
            AppLockGate.Decision.ShowLockedScreen(AppLockGate.LockedScreen.Unlock),
            decision,
        )
        assertFalse(decision.isUnlocked)
    }

    @Test
    fun `已解锁状态放行到密码库导航`() {
        val decision = AppLockGate.resolve(LockState.Unlocked("key-1"))
        assertEquals(AppLockGate.Decision.EnterVault, decision)
        assertTrue(decision.isUnlocked)
    }

    // ------------------------------------------------------------ 界面归属

    @Test
    fun `任何解锁界面都不可能被判定为已解锁`() {
        for (state in allStates.filterNot { it is LockState.Unlocked }) {
            assertFalse(
                "状态 $state 竟被判定为已解锁",
                AppLockGate.resolve(state).isUnlocked,
            )
        }
    }

    @Test
    fun `锁定与解锁前后判定必须翻转`() {
        // 这条用例模拟「库里被自动锁定」这一关键转折：
        // 判定必须随之翻转，否则锁定就只是改了个标志位，界面仍留在密码库上。
        assertTrue(allowsVault(LockState.Unlocked("key-1")))
        assertFalse("自动锁定后必须立刻停止渲染密码库界面", allowsVault(LockState.Locked))
    }
}
