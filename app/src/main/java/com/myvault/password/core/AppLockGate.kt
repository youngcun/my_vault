package com.myvault.password.core

import com.myvault.password.ui.LockState

/**
 * 界面准入闸门：把「会话状态」翻译成「此刻允许显示哪一个界面」。
 *
 * 为什么需要它（这里曾有一个真实缺陷）
 * --------------------------------
 * 界面此前**只用锁定状态决定 `NavHost` 的初始路由**（`startDestination`），
 * 而没有用它决定「哪些界面可以被渲染」。于是锁定状态与导航栈成了两个
 * 各自独立的事实来源：库一旦被锁定，`NavHost` 仍然停留在原来的路由上
 * （`vault` / `entry` / `settings` …），锁定并不等于「离开这些界面」。
 *
 * 对一个密码库来说这是不可接受的：**锁定必须是绝对的**。
 * 因此准入判定被抽成这个纯函数并单独测试 —— 任何「未解锁」状态
 * 都不可能映射到密码库界面，这条不变量由测试钉住，而不是靠自觉。
 *
 * 与 [AutoLockPolicy] 的分工：
 *  - [AutoLockPolicy] 回答「什么时候该锁」；
 *  - [AppLockGate] 回答「锁上以后能看见什么」。
 */
object AppLockGate {

    /** 未解锁时唯一允许存在的界面。 */
    sealed interface LockedScreen {
        /** 已创建密码库但尚未解锁：只能输入主密码 / 指纹。 */
        data object Unlock : LockedScreen

        /**
         * 还没有密码库（或信封读不出来）：只能走创建流程。
         *
         * 注意它与「未解锁」受同一条不变量保护：创建流程会**生成一份全新的
         * 密码库**，所以它在锁定状态下同样必须独占界面 —— 不能让用户在不
         * 解锁的情况下看到任何既有内容，也不能让创建流程与既有界面并存。
         */
        data object Setup : LockedScreen
    }

    /** 准入结果：要么只显示某一个解锁界面，要么进入密码库导航。 */
    sealed interface Decision {
        val isUnlocked: Boolean

        /** 未解锁：只显示 [screen]，其余界面一律不参与组合。 */
        data class ShowLockedScreen(val screen: LockedScreen) : Decision {
            override val isUnlocked: Boolean get() = false
        }

        /** 已解锁：允许渲染密码库导航图。 */
        data object EnterVault : Decision {
            override val isUnlocked: Boolean get() = true
        }
    }

    /**
     * 计算当前允许显示的界面。
     *
     * 判定是**白名单**：只有明确的 [LockState.Unlocked] 才放行，
     * 因此将来新增任何锁定状态，默认行为都是「留在解锁界面」，
     * 而不是悄悄获得进入密码库的资格。
     */
    fun resolve(state: LockState): Decision = when (state) {
        is LockState.Unlocked -> Decision.EnterVault
        LockState.Locked -> Decision.ShowLockedScreen(LockedScreen.Unlock)
        LockState.NeedsSetup -> Decision.ShowLockedScreen(LockedScreen.Setup)
        LockState.Loading -> Decision.ShowLockedScreen(LockedScreen.Unlock)
    }
}
