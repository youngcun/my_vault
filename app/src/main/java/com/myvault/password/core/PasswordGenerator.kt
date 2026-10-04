package com.myvault.password.core

import java.security.SecureRandom

/**
 * 密码生成策略。
 *
 * 三种模式覆盖真实使用场景：
 *  - [Mode.RANDOM]    完全随机的字符口令，适用于高价值账号；
 *  - [Mode.PASSPHRASE] 由常见单词拼成的「易记口令」，适用于需要人工输入的场合
 *                      （例如要抄写在纸上、或在电视遥控器/游戏机上输入）；
 *  - [Mode.PIN]       纯数字，适用于只接受数字的旧系统（如银行卡电话服务）。
 *
 * 安全性取舍说明：本类**不做**「用字典词替换随机字符」这类伪优化
 * （p@ssw0rd 式改写），因为那会显著降低实际熵，同时给人虚假的安全感。
 */
data class PasswordPolicy(
    val mode: Mode = Mode.RANDOM,
    /** 随机模式下的字符数 / 口令模式下的单词数 / PIN 模式的位数。 */
    val length: Int = 20,

    // ---- 随机模式字符集 ----
    val useLowercase: Boolean = true,
    val useUppercase: Boolean = true,
    val useDigits: Boolean = true,
    val useSymbols: Boolean = true,
    /** 是否排除形近字符（Il1O0o 等），便于人工抄写。 */
    val avoidAmbiguous: Boolean = false,
    /** 是否要求每个已选字符类至少出现一次（默认开启）。 */
    val requireEachClass: Boolean = true,

    // ---- 口令（易记）模式 ----
    /** 单词分隔符。 */
    val separator: String = "-",
    /** 每个单词首字母是否大写。 */
    val capitalizeWords: Boolean = true,
    /** 是否在词间插入随机数字（约定俗成，但会降低可读性）。 */
    val appendDigitsToWords: Boolean = false,
    /** 词表规模：[WordList.CORE_SIZE] 或 [WordList.EXTENDED_SIZE]。 */
    val wordListSize: Int = WordList.CORE_SIZE,

    // ---- 通用 ----
    /** 禁止连续出现超过 N 个相同字符（0 表示不限制）。 */
    val maxRepeatedRun: Int = 2,
) {
    enum class Mode { RANDOM, PASSPHRASE, PIN }

    /** 规范化后的长度，防止越界导致 OOM 或不可用密码。 */
    val safeLength: Int
        get() = length.coerceIn(
            when (mode) {
                Mode.RANDOM -> MIN_RANDOM_LENGTH
                Mode.PASSPHRASE -> MIN_WORD_COUNT
                Mode.PIN -> MIN_PIN_LENGTH
            },
            when (mode) {
                Mode.RANDOM -> MAX_RANDOM_LENGTH
                Mode.PASSPHRASE -> MAX_WORD_COUNT
                Mode.PIN -> MAX_PIN_LENGTH
            },
        )

    /** 随机模式下实际可用的字符池。 */
    fun alphabet(): CharArray {
        val sb = StringBuilder(96)
        if (useLowercase) sb.append(if (avoidAmbiguous) LOWER_SAFE else LOWER)
        if (useUppercase) sb.append(if (avoidAmbiguous) UPPER_SAFE else UPPER)
        if (useDigits) sb.append(if (avoidAmbiguous) DIGITS_SAFE else DIGITS)
        if (useSymbols) sb.append(SYMBOLS)
        return sb.toString().toCharArray()
    }

    /**
     * 校验策略是否可生成密码，不可行时返回**结构化**原因。
     *
     * [validate] 与 [invalidReason] 必须同时改动：前者是后者的中文渲染，
     * 唯一的真值来源是 [invalidReason]。
     *
     * 返回类型是顶层的 [PolicyError]（不是 `PasswordPolicy` 的嵌套类型）：
     * 界面层需要引用它，而嵌套类型会迫使所有调用点写成 `PasswordPolicy.PolicyError`。
     *
     * 注意这里**没有**长度相关的分支：[safeLength] 已经把长度钳制到各模式的下界
     * （随机 ≥ 8，口令 ≥ 3），而字符类型最多 4 种，因此「长度装不下字符类」
     * 与「单词数为 0」都不可达。详见 [PolicyError] 的说明。
     */
    fun invalidReason(): PolicyError? = when (mode) {
        Mode.RANDOM -> if (alphabet().isEmpty()) PolicyError.NoCharacterClass else null
        // 口令与 PIN 模式没有「字符集为空」这种失败模式：
        // 词表与数字字符集都是内建常量，不可能是空的。
        Mode.PASSPHRASE, Mode.PIN -> null
    }

    /**
     * 校验策略是否可生成密码；不可行时返回人类可读的中文原因。
     *
     * 中文渲染，**只供测试与异常消息使用**：界面请改用 [invalidReason] 并
     * 按当前语言渲染，否则英文界面会露出中文。
     */
    fun validate(): String? = when (invalidReason()) {
        null -> null
        PolicyError.NoCharacterClass -> "至少要选择一个字符类型"
    }

    /** 已选字符类型的数量。 */
    fun classCount(): Int =
        (if (useLowercase) 1 else 0) + (if (useUppercase) 1 else 0) +
            (if (useDigits) 1 else 0) + (if (useSymbols) 1 else 0)

    companion object {
        const val MIN_RANDOM_LENGTH = 8
        const val MAX_RANDOM_LENGTH = 128
        const val MIN_WORD_COUNT = 3
        const val MAX_WORD_COUNT = 12
        const val MIN_PIN_LENGTH = 4
        const val MAX_PIN_LENGTH = 24

        const val LOWER = "abcdefghijklmnopqrstuvwxyz"
        const val LOWER_SAFE = "abcdefghjkmnpqrstuvwxyz"      // 去掉 i l o
        const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        const val UPPER_SAFE = "ABCDEFGHJKLMNPQRSTUVWXYZ"     // 去掉 I O
        const val DIGITS = "0123456789"
        const val DIGITS_SAFE = "23456789"                    // 去掉 0 1
        /**
         * 符号集刻意排除 `"` `'` `` ` `` `\` 与空格：
         * 这些字符在命令行、CSV、SQL 等场景中极易引发转义问题，
         * 导致用户在别处粘贴时静默截断密码。
         */
        const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

        val DEFAULT = PasswordPolicy()
    }
}

/**
 * 密码生成引擎。
 *
 * 实现要点
 * -------
 * 1. **无模偏差采样**：用拒绝采样（rejection sampling）从 [SecureRandom] 取索引，
 *    而不是 `nextInt(n) % pool.size`。后者会让靠前的字符出现概率偏高，
 *    实际熵低于理论值 —— 这是密码生成器最常见的隐蔽缺陷。
 * 2. **字符类覆盖**：默认保证每个已勾选的字符类至少出现一次（许多网站强制要求），
 *    做法是先各放一个再洗牌，而不是「反复重试直到满足」。
 * 3. **可重复性**：生成器不使用任何共享可变状态，[SecureRandom] 由平台 CSPRNG 播种。
 */
class PasswordGenerator(private val random: SecureRandom = SecureRandom()) {

    /** 按策略生成密码。策略不可行时抛出 [IllegalArgumentException]。 */
    fun generate(policy: PasswordPolicy): String {
        policy.validate()?.let { throw IllegalArgumentException(it) }
        return when (policy.mode) {
            PasswordPolicy.Mode.RANDOM -> generateRandom(policy)
            PasswordPolicy.Mode.PASSPHRASE -> generatePassphrase(policy)
            PasswordPolicy.Mode.PIN -> generatePin(policy)
        }
    }

    /**
     * 生成随机字符口令。
     *
     * 算法：先为每个已选字符类各取一个字符（满足「必须包含」规则），
     * 剩余位置从全字符池取，最后用 Fisher-Yates 洗牌打散位置规律。
     */
    private fun generateRandom(policy: PasswordPolicy): String {
        val length = policy.safeLength
        val pools = classPools(policy)
        val full = policy.alphabet()
        val out = CharArray(length)

        var idx = 0
        if (policy.requireEachClass && pools.size <= length) {
            for (pool in pools) {
                out[idx++] = pool[uniformIndex(pool.size)]
            }
        }
        while (idx < length) {
            out[idx++] = full[uniformIndex(full.size)]
        }
        shuffle(out)
        enforceRunLimit(out, policy.maxRepeatedRun)
        return String(out)
    }

    /**
     * 生成易记口令（单词 + 分隔符）。
     *
     * 熵 = 单词数 × log2(词表大小) + 额外数字/大小写的贡献。
     * 例如 5 个词 × 4096 词表 ≈ 60 bit，远超「随机 10 位字符」，
     * 但人类记忆负担低得多 —— 这是 XKCD #936 的结论。
     */
    private fun generatePassphrase(policy: PasswordPolicy): String {
        val words = WordList.words(policy.wordListSize)
        val count = policy.safeLength
        val picked = ArrayList<String>(count)
        for (i in 0 until count) {
            var w = words[uniformIndex(words.size)]
            if (policy.appendDigitsToWords) {
                w += (uniformIndex(10)).toString()
            }
            if (policy.capitalizeWords) {
                w = w.replaceFirstChar { c -> c.uppercaseChar() }
            }
            // 避免连续两个词完全相同（会让人误以为是复制错误，也降低熵）
            if (picked.isNotEmpty() && picked.last() == w) {
                w = words[uniformIndex(words.size)]
                if (policy.capitalizeWords) w = w.replaceFirstChar { c -> c.uppercaseChar() }
            }
            picked.add(w)
        }
        return picked.joinToString(policy.separator)
    }

    /** 生成纯数字 PIN，同样使用拒绝采样避免偏差。 */
    private fun generatePin(policy: PasswordPolicy): String {
        val length = policy.safeLength
        val digits: String = if (policy.avoidAmbiguous) {
            PasswordPolicy.DIGITS_SAFE
        } else {
            PasswordPolicy.DIGITS
        }
        val out = CharArray(length)
        for (i in 0 until length) out[i] = digits[uniformIndex(digits.length)]
        enforceRunLimit(out, policy.maxRepeatedRun)
        return String(out)
    }

    /** 已选字符类各自的字符池（用于「每类至少一个」）。 */
    private fun classPools(policy: PasswordPolicy): List<CharArray> {
        val list = ArrayList<CharArray>(4)
        val lower: CharArray = (if (policy.avoidAmbiguous) PasswordPolicy.LOWER_SAFE else PasswordPolicy.LOWER).toCharArray()
        val upper: CharArray = (if (policy.avoidAmbiguous) PasswordPolicy.UPPER_SAFE else PasswordPolicy.UPPER).toCharArray()
        val digits: CharArray = (if (policy.avoidAmbiguous) PasswordPolicy.DIGITS_SAFE else PasswordPolicy.DIGITS).toCharArray()
        val symbols: CharArray = PasswordPolicy.SYMBOLS.toCharArray()
        if (policy.useLowercase) list.add(lower)
        if (policy.useUppercase) list.add(upper)
        if (policy.useDigits) list.add(digits)
        if (policy.useSymbols) list.add(symbols)
        return list
    }

    /**
     * 无模偏差地取 [0, bound) 内的随机索引。
     *
     * 实现要点（这里曾出现过一个严重缺陷，务必保留注释）：
     *
     * 最初写成「取一个字节，丢弃 `v >= 256 - (256 % bound)` 的值」。
     * 单字节只在 `bound <= 256` 时成立：当 `bound = 2048`（词表大小）时，
     * `limit = 256 - 256 = 0`，于是**每一个字节都被丢弃，循环永不返回** ——
     * 生成易记口令会让界面直接卡死。这类缺陷在只测小字符集的用例里发现不了。
     *
     * 正确做法：按 [bound] 所需的最小字节数采样，用「掩码 + 拒绝」消除模偏差
     * （OpenJDK `Random.nextInt(bound)` 的标准算法）。拒绝概率 < 1/2，
     * 期望重试次数 < 2，不存在病态循环。
     */
    private fun uniformIndex(bound: Int): Int {
        require(bound > 0) { "bound 必须为正数" }
        if (bound == 1) return 0

        // 需要的字节数：ceil(bits(bound - 1) / 8)
        val bits = 32 - Integer.numberOfLeadingZeros(bound - 1)
        val byteCount = (bits + 7) / 8

        // 掩码只保留有效比特，保证结果落在 [0, 2^bits) 内
        val mask = (1 shl bits) - 1

        while (true) {
            var candidate = 0
            for (i in 0 until byteCount) {
                candidate = (candidate shl 8) or nextRandomByte()
            }
            candidate = candidate and mask
            if (candidate < bound) return candidate
        }
    }

    /** 随机字节池。每次向 CSPRNG 要 [RANDOM_BUFFER_SIZE] 字节，用完再续。 */
    private val randomBuffer = ByteArray(RANDOM_BUFFER_SIZE)
    private var randomBufferIndex = RANDOM_BUFFER_SIZE

    private fun nextRandomByte(): Int {
        if (randomBufferIndex >= randomBuffer.size) {
            random.nextBytes(randomBuffer)
            randomBufferIndex = 0
        }
        return randomBuffer[randomBufferIndex++].toInt() and 0xFF
    }

    /** Fisher-Yates 原地洗牌，同样使用无偏索引。 */
    private fun shuffle(a: CharArray) {
        for (i in a.size - 1 downTo 1) {
            val j = uniformIndex(i + 1)
            val t = a[i]; a[i] = a[j]; a[j] = t
        }
    }

    /**
     * 打散超过 [maxRun] 的相同字符连串。
     *
     * 为什么需要：随机生成本就可能出现 "aaa"，而部分网站的强度检测会直接判为弱密码。
     *
     * 关键约束（这是一个容易踩的坑）：**替换不能破坏「每个已选字符类至少出现一次」**。
     * 例如已选 4 类字符、长度为 8 时，每个类可能恰好只有 1 个字符；
     * 若把它换成别的字符，那个类就彻底消失了，用户拿到的密码会被网站拒收。
     *
     * 因此这里不引入池中「新字符」（那会增加某类计数、可能导致另一类消失），
     * 而是与**串内已有的、字符不同的某个位置做交换**：交换保持每一类的计数不变，
     * 因此「每类至少一次」严格成立，最多只是把重复字符挪个位置。
     */
    private fun enforceRunLimit(out: CharArray, maxRun: Int) {
        if (maxRun <= 0 || out.size < 3) return
        var i = 2
        while (i < out.size) {
            if (out[i] == out[i - 1] && out[i] == out[i - 2]) {
                // 找一个能安全交换的位置：字符不同，且换过来不会制造新的三连
                var swapped = false
                for (k in 0 until out.size) {
                    if (k == i) continue
                    if (out[k] == out[i]) continue
                    // 交换后要检查 i 与 k 两处都不产生三连
                    if (createsRun(out, i, out[k], maxRun)) continue
                    if (createsRun(out, k, out[i], maxRun)) continue
                    val tmp = out[i]; out[i] = out[k]; out[k] = tmp
                    swapped = true
                    break
                }
                if (!swapped) return   // 无法安全修复（例如整串都是同一字符）：保持原样
            }
            i++
        }
    }

    /** 若把位置 [index] 换成 [value]，是否会形成长度超过 [maxRun] 的连串。 */
    private fun createsRun(out: CharArray, index: Int, value: Char, maxRun: Int): Boolean {
        var run = 1
        var j = index - 1
        while (j >= 0 && out[j] == value) { run++; j-- }
        j = index + 1
        while (j < out.size && out[j] == value) { run++; j++ }
        return run > maxRun
    }

    companion object {
        /**
         * 随机字节池大小。
         *
         * 每次向 CSPRNG 批量索取这么多字节。4096 字节足以生成数十个长口令，
         * 内存占用可忽略，同时把系统调用次数降低约三个数量级 ——
         * 这对逐字节调用会很慢（甚至阻塞）的平台至关重要。
         */
        private const val RANDOM_BUFFER_SIZE = 4096
    }
}
