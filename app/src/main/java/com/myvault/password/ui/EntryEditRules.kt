package com.myvault.password.ui

/**
 * 条目编辑界面的判定规则。
 *
 * 全部是**纯函数**：不依赖 Android、不读资源、不碰状态，因此可以被纯 JVM
 * 单元测试直接覆盖（这些规则决定的是「界面什么时候多做一次确认」，
 * 一旦判错，用户就会在不该被打断的地方被打断、或在真正危险的地方一路点过去）。
 */
object EntryEditRules {

    /**
     * 这次编辑是否改动了密码 —— 决定点击「保存」时是否需要二次确认。
     *
     * 为什么需要这个判定（真实风险）：
     * 密码字段在保存前是**可见**的（见 [com.myvault.password.ui.screens.EntryEditScreen]
     * 的注释）。这带来了一个副作用：用户从别的应用复制了一个新密码回到这里，
     * 若此时不小心从列表里点开了**另一条**记录，粘贴并保存就会静默覆盖
     * 那一条的旧密码 —— 而旧密码在本应用里从此不可恢复。
     * 二次确认框会点出当前条目的应用名称，正好把「改的是哪一条」摆到眼前。
     *
     * 三条刻意的取舍：
     *  1. **新建条目不确认**：此时没有「原来的密码」可覆盖，确认只会变成
     *     每次新建都要多点一下的噪音，最终让人形成「无脑点确定」的习惯 ——
     *     那反而会削弱真正需要确认时的效果。
     *  2. **按最终值判定，不记「中途改过」**：用户改了又改回原值，等于没改，
     *     不该再确认。判定只看「原密码 vs 当前值」，与编辑过程无关。
     *  3. **不做 trim / 大小写归一**：密码里的空格与大小写都是有意义的字符，
     *     把 `" Passw0rd"` 当成 `"passw0rd"` 会让判定放过真实的改动。
     *
     * @param isNew 是否新建条目（`entryId == null`）
     * @param originalPassword 打开编辑界面时该条目的密码；新建或读不到条目时为 null
     * @param currentPassword 密码输入框里的当前值
     */
    fun passwordChangedDuringEdit(
        isNew: Boolean,
        originalPassword: String?,
        currentPassword: String,
    ): Boolean {
        // 新建 = 没有原密码；条目读不出来时 originalPassword 也是 null ——
        // 两种情况下都不存在「覆盖旧密码」这件事，因此不拦。
        if (isNew) return false
        if (originalPassword == null) return false
        return originalPassword != currentPassword
    }
}
