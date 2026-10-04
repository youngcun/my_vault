package com.myvault.password.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 自动锁定策略测试。
 *
 * 背景：这里曾出现过一个真实缺陷 —— 定时器只在解锁时启动一次、从不因用户交互重置，
 * 导致**用户正在操作也会在解锁后固定时间被强制锁定**（表现为突然弹出解锁界面）。
 * 因此这些用例专门钉住「正在操作时绝不能锁」这一条不变量。
 */
class AutoLockPolicyTest {

    private val now = 1_700_000_000_000L
    private val minute = 60_000L

    // ------------------------------------------------------------ 从不锁定

    @Test
    fun `配置为从不时任何情况都不锁定`() {
        for (inForeground in listOf(true, false)) {
            for (idle in listOf(0L, minute, 10 * minute, 24 * 60 * minute)) {
                assertFalse(
                    "idle=$idle foreground=$inForeground 时不应锁定",
                    AutoLockPolicy.shouldLock(
                        configuredMillis = AutoLockPolicy.NEVER,
                        lastInteractionMillis = now - idle,
                        nowMillis = now,
                        inForeground = inForeground,
                    ),
                )
            }
        }
    }

    // ------------------------------------------------------------ 立即锁定

    @Test
    fun `立即模式在前台绝不锁定`() {
        // 这是最关键的一条：用户正在前台操作时，哪怕刚解锁也不许锁
        for (idle in listOf(0L, 1L, minute, 24 * 60 * minute)) {
            assertFalse(
                "立即模式在前台、idle=$idle 时不应锁定",
                AutoLockPolicy.shouldLock(
                    configuredMillis = AutoLockPolicy.IMMEDIATELY,
                    lastInteractionMillis = now - idle,
                    nowMillis = now,
                    inForeground = true,
                ),
            )
        }
    }

    @Test
    fun `立即模式在后台一律锁定`() {
        assertTrue(
            AutoLockPolicy.shouldLock(
                configuredMillis = AutoLockPolicy.IMMEDIATELY,
                lastInteractionMillis = now,
                nowMillis = now,
                inForeground = false,
            ),
        )
    }

    // ------------------------------------------------------------ 闲置超时

    @Test
    fun `前台闲置未达阈值时不锁定`() {
        // 覆盖「用户一直在操作」的场景：每次交互都会刷新时间戳，
        // 因此 idle 永远很小，绝不能被锁定。
        for (idle in listOf(0L, 1L, 30_000L, minute - 1)) {
            assertFalse(
                "idle=$idle 未达阈值 1 分钟，不应锁定",
                AutoLockPolicy.shouldLock(
                    configuredMillis = minute,
                    lastInteractionMillis = now - idle,
                    nowMillis = now,
                    inForeground = true,
                ),
            )
        }
    }

    @Test
    fun `前台闲置达到阈值时锁定`() {
        assertTrue(
            "闲置恰好等于阈值应锁定",
            AutoLockPolicy.shouldLock(
                configuredMillis = minute,
                lastInteractionMillis = now - minute,
                nowMillis = now,
                inForeground = true,
            ),
        )
        assertTrue(
            "闲置超过阈值应锁定",
            AutoLockPolicy.shouldLock(
                configuredMillis = minute,
                lastInteractionMillis = now - 5 * minute,
                nowMillis = now,
                inForeground = true,
            ),
        )
    }

    @Test
    fun `后台期间不做闲置判定`() {
        // 后台停留时长由「回到前台」的判定统一处理，
        // 避免两处逻辑各算一遍、结果还不一致。
        for (idle in listOf(0L, minute, 24 * 60 * minute)) {
            assertFalse(
                "后台 idle=$idle 时本函数不应直接锁定",
                AutoLockPolicy.shouldLock(
                    configuredMillis = minute,
                    lastInteractionMillis = now - idle,
                    nowMillis = now,
                    inForeground = false,
                ),
            )
        }
    }

    // ------------------------------------------------------------ 异常输入

    @Test
    fun `时间戳异常时不锁定用户`() {
        // 时钟回拨（用户改了系统时间、NTP 校正）：宁可继续可用，
        // 也不要把用户锁在外面 —— 这是可用性优先的保守选择。
        assertFalse(
            "lastInteraction 在未来时不应锁定",
            AutoLockPolicy.shouldLock(
                configuredMillis = minute,
                lastInteractionMillis = now + 10 * minute,
                nowMillis = now,
                inForeground = true,
            ),
        )
    }

    @Test
    fun `零点时间戳被视为刚解锁不会被立刻锁定`() {
        // lastInteractionAt 初始为 0（本次解锁后还没交互）时，
        // 若直接参与计算会被判为「闲置了 55 年」而瞬间锁定。
        // 因此 ViewModel 会先补基准值；这里验证 0 与 now 的组合行为符合直觉：
        // 0 作为「很久以前」在达到阈值时确实会锁 ——
        // 这正是要求 ViewModel 必须先补基准的原因，用例把它文档化。
        assertTrue(
            "lastInteraction=0 且已超阈值时判为应锁定（故 ViewModel 必须先补基准值）",
            AutoLockPolicy.shouldLock(
                configuredMillis = minute,
                lastInteractionMillis = 0L,
                nowMillis = now,
                inForeground = true,
            ),
        )
    }

    @Test
    fun `短超时配置同样遵循交互重置语义`() {
        // 配置 30 秒：只要用户在 30 秒内有操作就不会锁
        val configured = 30_000L
        assertFalse(
            AutoLockPolicy.shouldLock(configured, now - 29_000L, now, inForeground = true),
        )
        assertTrue(
            AutoLockPolicy.shouldLock(configured, now - 30_000L, now, inForeground = true),
        )
    }

    // ------------------------------------------------------------ 会话保持

    @Test
    fun `会话保持期间任何配置下都不锁定`() {
        // 「应用自己发起的流程」= 前台会话的延续：SAF 文件选择器、备份文件的读写。
        // 它必须压过全部三种配置，否则用户点完导出、在系统选择器里挑保存位置时，
        // 密码库就被锁了（导出随即失败，而且以前是静默失败）。
        for (configured in listOf(AutoLockPolicy.IMMEDIATELY, 30_000L, minute, AutoLockPolicy.NEVER)) {
            for (inForeground in listOf(true, false)) {
                for (idle in listOf(0L, minute, 24 * 60 * minute)) {
                    assertFalse(
                        "保持期间 configured=$configured fg=$inForeground idle=$idle 不该锁定",
                        AutoLockPolicy.shouldLock(
                            configuredMillis = configured,
                            lastInteractionMillis = now - idle,
                            nowMillis = now,
                            inForeground = inForeground,
                            sessionHold = true,
                        ),
                    )
                }
            }
        }
    }

    @Test
    fun `会话保持不改变其余判定_没有保持时行为与原来一致`() {
        // 保持是**显式申请**的：默认值为 false 时，三种配置的行为必须一字不变，
        // 否则「暂停自动锁定」会变成默认行为，那等于悄悄取消了自动锁定。
        assertTrue(
            AutoLockPolicy.shouldLock(
                configuredMillis = AutoLockPolicy.IMMEDIATELY,
                lastInteractionMillis = now,
                nowMillis = now,
                inForeground = false,
                sessionHold = false,
            ),
        )
        assertTrue(
            AutoLockPolicy.shouldLock(
                configuredMillis = minute,
                lastInteractionMillis = now - minute,
                nowMillis = now,
                inForeground = true,
                sessionHold = false,
            ),
        )
        assertTrue(
            "省略 sessionHold（默认 false）时，闲置达标照常锁定",
            AutoLockPolicy.shouldLock(
                configuredMillis = minute,
                lastInteractionMillis = now - minute,
                nowMillis = now,
                inForeground = true,
            ),
        )
    }
}
