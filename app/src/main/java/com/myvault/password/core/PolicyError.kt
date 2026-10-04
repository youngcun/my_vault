package com.myvault.password.core

/**
 * 「当前生成器策略无法生成密码」的结构化原因。
 *
 * ## 为什么是一个类型，而不是一句现成的文案
 *
 * `core/` 包刻意不依赖任何 Android 类（见 README §4），因此这里**不能**取字符串资源；
 * 而这条提示又必须按用户当前的语言显示。若在 `core/` 里直接拼一句中文，
 * 英文界面下就会露出中文 —— 这正是本地化最容易漏掉的一类漏洞。
 *
 * 所以这里只回答**是哪一类问题**，具体措辞由界面层
 * （`ui/components/Common.kt` 的 `policyErrorText`）决定。
 * [PasswordPolicy.validate] 仍提供中文渲染，供纯 JVM 测试与异常消息使用。
 *
 * ## 为什么只有一个分支（这不是「还没写完」）
 *
 * 本类型最初有三个分支，其中两个是**不可达**的，已删除：
 *
 *  - 「长度装不下已勾选的字符类型」：字符类型最多 4 种，而
 *    [PasswordPolicy.safeLength] 把随机模式钳制到至少
 *    [PasswordGenerator.MIN_RANDOM_LENGTH]（= 8），因此
 *    `safeLength < classCount()` 永远为假；
 *  - 「易记口令单词数为 0」：`safeLength` 对口令模式钳制到至少
 *    [PasswordGenerator.MIN_WORD_COUNT]（= 3），因此 `safeLength < 1` 永远为假。
 *
 * 换句话说，**长度越界在构造策略时就被钳制掉了**，根本到不了校验这一步；
 * 真正能让策略不可行的只有「一个字符类型都没选」。保留一个骗人的分支会让
 * 界面写出一条永远不会显示的提示，也会让读者以为存在实际不存在的失败模式。
 * 这个结论由 `PasswordGeneratorTest` 里的 `长度被钳制后不可能装不下字符类` 钉住。
 */
sealed interface PolicyError {
    /** 一个字符类型都没选 —— 唯一真正可达的不可行原因。 */
    data object NoCharacterClass : PolicyError
}
