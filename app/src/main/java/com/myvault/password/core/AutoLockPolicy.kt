package com.myvault.password.core

/**
 * 自动锁定策略（纯逻辑，可单元测试）。
 *
 * 为什么要把这段逻辑单独抽出来
 * -------------------------
 * 「什么时候该锁」是密码库最关键的行为之一，而它同时取决于三个输入：
 * 用户配置的超时、最后一次交互时间、应用是否在前台。
 * 把这三种情况的组合写进 ViewModel 里既难测也容易出错 ——
 * 本应用曾经就因为「定时器只在解锁时启动、从不因操作重置」
 * 导致解锁后固定 3 分钟必锁（用户正在操作也会被打断）。
 *
 * 这里定义成无副作用的纯函数，用真值表覆盖全部边界。
 *
 * 与 [AutoLockSession] 的分工：
 *  - [AutoLockSession] 持有状态（最后交互时间、进行中的流程）；
 *  - [AutoLockPolicy] 只回答「以这些输入来看，现在该不该锁」。
 */
object AutoLockPolicy {

    /** 「从不自动锁定」的配置值。 */
    const val NEVER = -1L

    /** 「一进入后台就锁定」的配置值。 */
    const val IMMEDIATELY = 0L

    /**
     * 现在是否应该锁定。
     *
     * @param configuredMillis 用户配置的超时；负数表示从不
     * @param lastInteractionMillis 最后一次用户交互的时间戳
     * @param nowMillis 当前时间
     * @param inForeground 应用当前是否处于前台
     * @param sessionHold 是否有**应用自己发起的**流程仍在进行（SAF 文件选择器、
     *   备份文件的读写）。这类流程会让应用进入后台，但用户并没有离开 ——
     *   因此它是「前台会话的延续」，任何配置下都不该锁定。
     *
     *   ⚠️ 不要把它理解成「有对话框打开就别锁」：这里的保持是**显式申请**的，
     *   只覆盖应用自己发起、且有明确结束点的那几段流程；用户交互则走
     *   [lastInteractionMillis]（打字即交互，停下就按超时锁）。
     */
    fun shouldLock(
        configuredMillis: Long,
        lastInteractionMillis: Long,
        nowMillis: Long,
        inForeground: Boolean,
        sessionHold: Boolean = false,
    ): Boolean {
        // 用户明确选择「从不」：任何情况下都不主动锁定
        if (configuredMillis < 0) return false

        // 应用自己发起的流程仍在进行：视为前台会话的延续。
        // 必须放在「立即」判定之前 —— 文件选择器本身就会让应用进入后台，
        // 若先判后台，用户还在挑保存位置时库就被锁了（缺陷 #15）。
        if (sessionHold) return false

        // 「立即」只在离开前台后生效 ——
        // 绝不能在前台把正在操作的用户锁掉
        if (configuredMillis == 0L) return !inForeground

        // 只有在前台才有「闲置超时」的概念。
        // 后台停留时长由「回到前台」时的判定处理（见 ViewModel.onEnterForeground）。
        if (!inForeground) return false

        // 时钟回拨或异常时间戳：宁可继续用，也不要把用户锁在外面
        if (nowMillis < lastInteractionMillis) return false

        return nowMillis - lastInteractionMillis >= configuredMillis
    }
}
