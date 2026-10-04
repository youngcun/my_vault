package com.myvault.password.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 自动锁定会话状态测试。
 *
 * 背景（这是一个真实缺陷，用户报告为「导出加密备份时 app 锁屏，操作中断」）：
 * 自动锁定只认「最后一次指针触摸」，于是漏掉了两类真实交互 ——
 * 对话框里的输入（独立窗口）与软键盘输入（不产生指针事件）；
 * 而「应用自己发起的流程仍在进行」（SAF 选择器、备份读写）也完全没有被表达。
 *
 * 这些用例专门钉住两条不变量：
 *  1. **有流程在保持会话时，任何配置都不锁定** —— 包括「立即」+后台
 *     （文件选择器会让应用进入后台，但用户并没有离开）；
 *  2. **保持的申请与释放必须安全**：释放不会「欠账」，重复申请不需要重复释放，
 *     否则会出现「保持泄漏 ⇒ 自动锁定被永久关闭」这种比多锁一次严重得多的后果。
 */
class AutoLockSessionTest {

    private var now = 1_700_000_000_000L
    private val session = AutoLockSession(clock = { now })

    private val minute = 60_000L

    private fun advance(millis: Long) {
        now += millis
    }

    // ------------------------------------------------------------ 交互驱动

    @Test
    fun `闲置未达阈值不锁定_达到阈值才锁定`() {
        advance(minute - 1)
        assertFalse(session.shouldLock(minute, inForeground = true))

        advance(1)
        assertTrue("闲置恰好达到阈值应锁定", session.shouldLock(minute, inForeground = true))
    }

    @Test
    fun `用户交互会重置闲置基准`() {
        advance(minute - 1)
        session.onUserInteraction()
        advance(minute - 1)
        assertFalse("最后交互之后又过了 59 秒，仍不该锁", session.shouldLock(minute, inForeground = true))
    }

    @Test
    fun `会话开始会重置闲置基准`() {
        // 解锁那一刻必须重新计时，否则「离开 2 小时后回来解锁」会被立刻再锁一次
        advance(2 * 60 * minute)
        session.markSessionStart()
        assertFalse(session.shouldLock(minute, inForeground = true))
    }

    @Test
    fun `构造后未发生任何交互也不会被立刻锁定`() {
        // 零点时间戳陷阱：lastInteraction 若为 0 会被算成「闲置了 55 年」。
        // 本类在构造时就补了基准值，这条用例把它钉住。
        assertFalse(session.shouldLock(minute, inForeground = true))
    }

    // ------------------------------------------------------------ 会话保持

    @Test
    fun `保持期间任何配置都不锁定`() {
        session.hold(AutoLockSession.HOLD_SYSTEM_PICKER)
        advance(24 * 60 * minute)   // 在选择器里挑了一整天

        for (configured in listOf(AutoLockPolicy.IMMEDIATELY, 30_000L, minute, AutoLockPolicy.NEVER)) {
            for (inForeground in listOf(true, false)) {
                assertFalse(
                    "保持期间 configured=$configured inForeground=$inForeground 都不该锁定",
                    session.shouldLock(configured, inForeground = inForeground),
                )
            }
        }
    }

    @Test
    fun `保持必须优先于立即模式的后台判定`() {
        // 这是缺陷 #15 / #24 的核心：SAF 选择器是另一个 Activity，
        // 打开它必然让应用进入后台。若「立即」先判后台，用户还在挑保存位置时库就被锁了。
        assertTrue(
            "无保持时：立即模式在后台就该锁",
            session.shouldLock(AutoLockPolicy.IMMEDIATELY, inForeground = false),
        )

        session.hold(AutoLockSession.HOLD_SYSTEM_PICKER)
        assertFalse(
            "有保持时：后台也不锁（应用自己发起的外部界面 = 前台会话的延续）",
            session.shouldLock(AutoLockPolicy.IMMEDIATELY, inForeground = false),
        )
    }

    @Test
    fun `释放保持后不会因为保持期间的时长被立刻锁定`() {
        session.hold(AutoLockSession.HOLD_BACKUP_IO)
        advance(30 * minute)       // 写备份用了 30 分钟
        session.release(AutoLockSession.HOLD_BACKUP_IO)

        assertFalse("刚做完一件事不该立刻被锁", session.shouldLock(minute, inForeground = true))
        advance(minute)
        assertTrue("释放之后闲置时间照常累积", session.shouldLock(minute, inForeground = true))
    }

    @Test
    fun `每一次导出都受保护而不是只有第一次`() {
        // 回归用例：桥接实现里第一次选择器返回后引用被置空，
        // 于是同一个解锁会话里的第二次导出彻底失去豁免。
        // 现在状态只有一份，反复申请/释放必须每次都有效。
        repeat(3) { round ->
            session.hold(AutoLockSession.HOLD_SYSTEM_PICKER)
            advance(5 * minute)
            assertFalse(
                "第 ${round + 1} 次导出：文件选择期间不该锁定",
                session.shouldLock(AutoLockPolicy.IMMEDIATELY, inForeground = false),
            )
            session.release(AutoLockSession.HOLD_SYSTEM_PICKER)
            assertFalse(session.isHeld)
            advance(1_000)
        }
    }

    // ------------------------------------------------------------ 申请 / 释放的健壮性

    @Test
    fun `重复申请同一原因只需释放一次`() {
        session.hold(AutoLockSession.HOLD_BACKUP_IO)
        session.hold(AutoLockSession.HOLD_BACKUP_IO)
        session.release(AutoLockSession.HOLD_BACKUP_IO)
        assertFalse("原因是状态而不是计数，重复申请不该需要重复释放", session.isHeld)
    }

    @Test
    fun `释放尚未申请的原因不会误释放其他保持`() {
        // 计数器实现会在这里下溢：释放一个不存在的保持把仍在进行的保持抹掉，
        // 后果是「导出进行到一半自动锁定重新生效」。
        session.hold(AutoLockSession.HOLD_BACKUP_IO)
        session.release(AutoLockSession.HOLD_SYSTEM_PICKER)
        assertTrue("释放未知原因必须是空操作", session.isHeld)
    }

    @Test
    fun `多个原因相互独立_释放一个仍然保持`() {
        session.hold(AutoLockSession.HOLD_SYSTEM_PICKER)
        session.hold(AutoLockSession.HOLD_BACKUP_IO)
        session.release(AutoLockSession.HOLD_SYSTEM_PICKER)

        assertTrue("还有另一个原因在保持", session.isHeld)
        advance(10 * minute)
        assertFalse(session.shouldLock(minute, inForeground = true))

        session.release(AutoLockSession.HOLD_BACKUP_IO)
        assertFalse(session.isHeld)
    }

    @Test
    fun `clearHolds 一次性释放全部保持`() {
        // Activity 销毁时必须能一次收回：残留保持 = 自动锁定被永久关闭
        session.hold(AutoLockSession.HOLD_SYSTEM_PICKER)
        session.hold(AutoLockSession.HOLD_BACKUP_IO)
        session.clearHolds()

        assertFalse(session.isHeld)
        assertTrue(session.activeHolds().isEmpty())
        advance(10 * minute)
        assertTrue(session.shouldLock(minute, inForeground = true))
    }

    @Test
    fun `保持原因可枚举_便于排错`() {
        session.hold(AutoLockSession.HOLD_SYSTEM_PICKER)
        session.hold(AutoLockSession.HOLD_BACKUP_IO)
        assertEquals(
            setOf(AutoLockSession.HOLD_SYSTEM_PICKER, AutoLockSession.HOLD_BACKUP_IO),
            session.activeHolds(),
        )
    }
}
