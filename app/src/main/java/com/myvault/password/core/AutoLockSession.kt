package com.myvault.password.core

/**
 * 自动锁定的**会话状态**：唯一的真值来源。
 *
 * 为什么把它从 ViewModel 里搬出来（这里曾有一个真实缺陷）
 * ----------------------------------------------------
 * 「什么时候该锁」需要两类输入：
 *
 *  1. **用户交互**（触摸、文字输入）—— 由界面层产生；
 *  2. **应用自己发起的流程仍在进行**（SAF 文件选择器、备份读写）—— 由 Activity 产生，
 *     而 Activity 拿不到导航作用域里的 `MainViewModel`。
 *
 * 第 2 类输入此前靠一条「Compose 组合期注册的回调桥」从 Activity 传进 ViewModel。
 * 那条桥自己成了缺陷来源：Activity 在第一次选择器返回后把桥的引用置空
 * （`pickerLifecycle = null`），于是**同一个解锁会话里的第二次导出不再有任何豁免**，
 * 用户还在挑保存目录时密码库就被锁了 —— 症状与已修复的缺陷 #15 一模一样，
 * 只是触发条件更隐蔽（第一次导出正常，第二次才复现）。
 *
 * 现在改为：会话状态由本对象持有，并放进 [com.myvault.password.AppContainer]
 * （与 Application 同生命周期）。Activity 与 ViewModel **各自直接读写同一份状态**，
 * 不再需要任何组合期注册的中间层 —— 少一个中间层，就少一类「中间层自己坏了」的缺陷。
 *
 * 本对象不持有任何秘密（只有一个时间戳与若干原因名），因此可以安全地放在应用级容器里；
 * 它也不依赖任何 Android 类，可以在纯 JVM 上把语义钉死（见 `AutoLockSessionTest`）。
 *
 * 两类输入的语义差别（这一点很关键，不要合并成「一个布尔」）
 * ------------------------------------------------------
 * | 输入 | 表现 | 后台时是否仍然豁免 |
 * | --- | --- | --- |
 * | 用户交互 | 刷新闲置计时基准 | 否（后台该锁就锁） |
 * | 会话保持（[hold]） | 完全暂停自动锁定 | **是**（选择器/写文件时应用本来就在后台） |
 */
class AutoLockSession(
    private val clock: () -> Long = System::currentTimeMillis,
) {

    /**
     * 当前保持会话的原因集合。
     *
     * 用**原因集合**而不是计数器：原因是一种状态，不是一个计数。
     *  - `hold` 幂等 —— 重复申请同一个原因不需要重复释放；
     *  - `release` 只移除自己那一个原因 —— 释放一个已释放/未知的原因是无操作，
     *    永远不会「欠账」（计数器在重复释放时会下溢，从而把仍然存在的保持抹掉）。
     */
    private val holds = LinkedHashSet<String>()

    /**
     * 最后一次用户交互的时间戳。
     *
     * 构造时即取当前时间：这样「进程刚起来还没人碰过」不会被判成
     * 「闲置了 55 年」而瞬间锁定（零点时间戳陷阱，见 [AutoLockPolicy]）。
     */
    private var lastInteractionAt: Long = clock()

    /** 用户产生了交互（触摸、文字输入）。 */
    @Synchronized
    fun onUserInteraction() {
        lastInteractionAt = clock()
    }

    /**
     * 会话开始（解锁成功）。
     *
     * 闲置时间必须从这一刻重新计时，否则本次会话会立刻被判为闲置。
     */
    @Synchronized
    fun markSessionStart() {
        lastInteractionAt = clock()
    }

    /** 申请「暂停自动锁定」。幂等，必须与 [release] 成对使用（同一个 [reason]）。 */
    @Synchronized
    fun hold(reason: String) {
        holds.add(reason)
        // 保持开始时重置基准：保持期间不该累积任何闲置时间
        lastInteractionAt = clock()
    }

    /**
     * 释放申请。
     *
     * 无论是否还有其他保持，都会重置闲置基准 —— 释放的那一刻正是
     * 「应用刚回到前台」或「刚做完一件事」，闲置时间应当从这里重新算，
     * 而不是把保持期间的时长一次性算进闲置。
     */
    @Synchronized
    fun release(reason: String) {
        holds.remove(reason)
        lastInteractionAt = clock()
    }

    /**
     * 释放全部保持。
     *
     * 由 Activity 在 [android.app.Activity.onDestroy] 时调用：Activity 一旦销毁，
     * 它发起的流程不可能再完成，任何残留的保持都必须清掉 ——
     * 「自动锁定被永久关闭」是比「多锁一次」严重得多的缺陷。
     */
    @Synchronized
    fun clearHolds() {
        holds.clear()
        lastInteractionAt = clock()
    }

    /** 当前是否有流程在保持会话。 */
    val isHeld: Boolean
        @Synchronized get() = holds.isNotEmpty()

    /** 当前保持中的原因快照（只读，便于排错与自证）。 */
    @Synchronized
    fun activeHolds(): Set<String> = holds.toSet()

    /**
     * 唯一的判定入口：看门狗与「回到前台」都必须走这里。
     *
     * 之所以不各自调用 [AutoLockPolicy]：判定需要同时看「交互时间 + 保持状态」，
     * 两处各写一遍迟早会漏掉其中一项。
     */
    @Synchronized
    fun shouldLock(
        configuredMillis: Long,
        inForeground: Boolean,
        nowMillis: Long = clock(),
    ): Boolean = AutoLockPolicy.shouldLock(
        configuredMillis = configuredMillis,
        lastInteractionMillis = lastInteractionAt,
        nowMillis = nowMillis,
        inForeground = inForeground,
        sessionHold = holds.isNotEmpty(),
    )

    /** 仅供测试与排错：当前闲置基准时刻。 */
    @Synchronized
    fun lastInteractionMillis(): Long = lastInteractionAt

    companion object {
        /**
         * 保持原因：应用自己发起的系统文件选择器（SAF）正在进行。
         *
         * 选择器是**另一个 Activity**，打开它会让本应用进入后台 ——
         * 若不加保持，用户还在挑保存位置时密码库就被锁了（缺陷 #15）。
         */
        const val HOLD_SYSTEM_PICKER = "system-picker"

        /**
         * 保持原因：备份文件的读/写正在进行。
         *
         * 这一段包含全库快照解密与 Argon2id（数十 MiB 内存、秒级 CPU）。
         * 期间用户不会碰屏幕，但这不是「闲置」—— 他是点完导出在等结果。
         */
        const val HOLD_BACKUP_IO = "backup-io"
    }
}
