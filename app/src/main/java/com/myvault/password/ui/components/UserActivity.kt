package com.myvault.password.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput

/**
 * 「用户正在操作」的上报通道。
 *
 * 为什么需要一条显式通道（这里曾有一个真实缺陷）
 * --------------------------------------------
 * 自动锁定的唯一依据是「最后一次用户交互」。原先只有一处上报点：
 * 已解锁界面根容器上的 `pointerInput`。它看起来「所有触摸都会经过」，
 * 实际上漏掉了两类真实交互：
 *
 *  1. **对话框**。`BackupPassphraseDialog` / `PasswordConfirmDialog` 都是 Compose
 *     `Dialog`，内容渲染在**另一个窗口**里 —— 那里的触摸事件根本不会经过
 *     Activity 窗口中的根容器。于是「打开导出对话框 → 慢慢输入备份口令」这段
 *     时间在自动锁定看来完全是闲置的：默认超时 60 秒，而一个长口令要输两遍。
 *     结果就是**用户正在输入备份口令时应用锁定**，对话框消失、导出中断。
 *  2. **软键盘输入（IME）**。软键盘属于输入法自己的窗口，提交文字走
 *     `InputConnection`，**不产生任何指针事件** —— 因此「一直在打字」在旧的
 *     判定里与「什么都没做」完全一样。
 *
 * 两类漏报的后果相同：用户正在操作，应用却判定他闲置。
 * 因此把上报做成通道，让「能观察到用户的地方」都能报一次，而不是继续往
 * 根容器上堆手势监听。
 *
 * 语义边界（很重要）：上报只**刷新闲置计时基准**，它不会暂停自动锁定 ——
 * 用户停止输入后，超时照常生效。真正需要「暂时不许锁」的是应用自己发起的
 * 流程（文件选择器、备份读写），那一类用
 * [com.myvault.password.core.AutoLockSession.hold] 显式申请。
 */
val LocalUserActivity = staticCompositionLocalOf<() -> Unit> { {} }

/**
 * 让这段界面里的任何触摸都算作「用户交互」。
 *
 * 用在**独立窗口**里的内容上（对话框）：根容器收不到那些触摸。
 * `pointerInput` 不影响布局，只是旁听事件。
 */
@Composable
fun Modifier.reportsUserActivity(): Modifier {
    // 用 rememberUpdatedState 持有回调：parent 重新组合时不会重启 pointerInput 循环
    val reporter = rememberUpdatedState(LocalUserActivity.current)
    return this.pointerInput(Unit) {
        awaitPointerEventScope {
            while (true) {
                // 只旁听、不消费：滚动与点击照常传给下层控件
                awaitPointerEvent()
                reporter.value()
            }
        }
    }
}
