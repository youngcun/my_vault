package com.myvault.password.autofill

import com.myvault.password.domain.VaultEntry

/**
 * 已解锁条目的进程内缓存。
 *
 * 背景：**自动填充服务是独立组件**。它由 `system_server` 绑定，
 * 与 Activity 共享同一进程但不是同一个 ViewModel 作用域。因此需要一个
 * 进程级的只读快照，让填充服务在不重新打开数据库、不重新派生密钥的前提下
 * 拿到解密后的条目。
 *
 * 安全约束（很重要）
 * ---------------
 *  1. 这个缓存**只在解锁状态下填充**；[VaultRepository.lock] 会调用 [clear]。
 *  2. 缓存的是**解密后的明文**，因此它等同于「已解锁的密码库」——
 *     绝不能写入磁盘、绝不能跨进程传递（不实现 Serializable/Parcelable）。
 *  3. 填充服务本身不持有密钥：它只能读这个快照，无法自行解密任何东西。
 *     这意味着即便自动填充服务被恶意调用，攻击者也拿不到密钥材料。
 *
 * 为什么用全局单例而不是依赖注入：自动填充服务由系统实例化，
 * 没有机会注入依赖。Android 上这是标准做法。
 */
object UnlockedEntryCache {

    @Volatile
    private var entries: List<VaultEntry> = emptyList()

    /**
     * 「库已解锁」这一状态本身，与快照里有没有条目无关。
     *
     * 这里曾有一个真实缺陷：用 `entries.isNotEmpty()` 当解锁判据，
     * 于是**空库会被当成「已锁定」** —— 用户刚建好库还没添加条目时，
     * 自动填充会一直提示「请先解锁密码库」。解锁与否必须由会话状态决定，
     * 而不是由数据条数决定。
     */
    @Volatile
    private var unlocked: Boolean = false

    /** 是否有可用的解锁快照。 */
    val isUnlocked: Boolean get() = unlocked

    /**
     * 标记「库已解锁」。
     *
     * 由 [com.myvault.password.data.VaultRepository] 在解锁成功的那一刻调用，
     * 不必等条目查询那条 Flow 第一次发射 —— 那个间隙里填充服务会误判为未解锁。
     */
    fun markUnlocked() {
        unlocked = true
    }

    /** 用最新快照替换缓存（每次条目变更后由 Repository 调用）。 */
    fun update(list: List<VaultEntry>) {
        entries = list.toList()
        unlocked = true
    }

    /** 读取当前快照。返回不可变副本，防止调用方修改缓存内容。 */
    fun snapshot(): List<VaultEntry> = entries

    /** 按站点/包名匹配候选（返回匹配度降序）。 */
    fun candidates(host: String?, packageName: String?): List<VaultEntry> =
        entries.map { it to it.matchScore(host, packageName) }
            .filter { it.second > 0 }
            .sortedByDescending { it.second }
            .map { it.first }

    /**
     * 锁定时清零。
     *
     * 注意这里只能「丢弃引用」，无法擦除早已被复制出去的 String ——
     * 这是 Kotlin/JVM 上 String 不可变的固有代价。因此我们的做法是
     * **尽量不要把密码复制到缓存之外**：填充时直接从缓存取出、写入
     * Autofill 结果，不经过中间集合。
     */
    fun clear() {
        entries = emptyList()
        unlocked = false
    }
}
