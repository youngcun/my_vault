package com.myvault.password.util

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log

/**
 * 剪贴板工具。
 *
 * 为什么需要它
 * -----------
 * 复制密码到剪贴板是密码管理器最容易被利用的环节：
 *  - Android 10 之前，任何后台应用都能读取剪贴板；
 *  - 输入法、剪贴板历史应用会长期保留复制内容；
 *  - 因此密码可能在你毫无察觉的情况下被其他应用捡走。
 *
 * 本类的缓解措施：
 *  1. 复制密码时标记 `ClipDescription.EXTRA_IS_SENSITIVE`（Android 13+），
 *     系统就不会在剪贴板预览浮层里显示明文；
 *  2. 到时间后主动清空剪贴板（而不是只标记，因为标记在旧系统上无效）；
 *  3. 主动清空时会先核对「剪贴板里还是我们放进去的那段内容」，
 *     避免把用户后来复制的东西误删。
 */
object ClipboardHelper {

    private const val TAG = "ClipboardHelper"

    private val handler = Handler(Looper.getMainLooper())

    /** 记录当前由本应用投放的敏感内容，用于安全地按内容比对后再清除。 */
    @Volatile
    private var pendingSensitive: String? = null

    private var clearRunnable: Runnable? = null

    /**
     * 复制文本到剪贴板。
     *
     * @param sensitive 是否为敏感内容（密码 / 主密码）。敏感内容会被标记并定时清除。
     * @param clearAfterMillis 多久后清除；传 0 或负数表示不清除。
     * @param onCleared 清除完成后的回调（用来更新界面提示）
     */
    fun copy(
        context: Context,
        label: String,
        text: String,
        sensitive: Boolean,
        clearAfterMillis: Long,
        onCleared: (() -> Unit)? = null,
    ) {
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(label, text)
        if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // Android 13 起，系统会隐藏带此标记的剪贴板预览
            clip.description.extras = android.os.PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
        }
        try {
            manager.setPrimaryClip(clip)
        } catch (e: Exception) {
            // 少数 ROM 在应用处于后台时会拒绝写剪贴板；静默失败但不影响主流程
            Log.w(TAG, "写入剪贴板失败：${e.message}")
            return
        }

        if (!sensitive || clearAfterMillis <= 0) return

        pendingSensitive = text
        clearRunnable?.let { handler.removeCallbacks(it) }
        val runnable = Runnable {
            clearIfStillOurs(context, text, onCleared)
        }
        clearRunnable = runnable
        handler.postDelayed(runnable, clearAfterMillis)
    }

    /**
     * 只有当剪贴板内容仍然是我们放进去的那段文本时才清空。
     * 直接无条件清空会破坏用户之后的复制操作，是很讨人厌的行为。
     */
    private fun clearIfStillOurs(context: Context, expected: String, onCleared: (() -> Unit)?) {
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        try {
            val current = manager.primaryClip
                ?.takeIf { it.itemCount > 0 }
                ?.getItemAt(0)
                ?.coerceToText(context)
                ?.toString()
            if (current != null && current == expected) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    manager.clearPrimaryClip()
                } else {
                    manager.setPrimaryClip(ClipData.newPlainText("", ""))
                }
                onCleared?.invoke()
            }
        } catch (e: Exception) {
            Log.w(TAG, "清除剪贴板失败：${e.message}")
        } finally {
            pendingSensitive = null
            clearRunnable = null
        }
    }

    /** 应用退出或锁定时立即清除（不等定时器）。 */
    fun clearNow(context: Context) {
        val expected = pendingSensitive ?: return
        clearRunnable?.let { handler.removeCallbacks(it) }
        clearIfStillOurs(context, expected, null)
    }
}
