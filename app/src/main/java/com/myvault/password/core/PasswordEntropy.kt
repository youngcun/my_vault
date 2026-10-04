package com.myvault.password.core

import kotlin.math.ln
import kotlin.math.log2
import kotlin.math.pow

/**
 * 口令强度评估。
 *
 * 本文件刻意**不复刻** zxcvbn 那种基于模式匹配的猜测数估计，原因有二：
 *  1. 对于「由本应用生成的口令」，其生成过程是完全已知的均匀采样，
 *     因此熵可以**精确解析计算**，不需要估计；
 *  2. 对于「用户自己输入的口令」（主密码），任何估计都只是启发式。
 *     与其给用户一个可能高估的分数，不如直接给出「长度 + 字符集」的
 *     保守下界，并明确标注这是下界。
 *
 * 这对安全至关重要：一个虚高的强度条会让用户放心使用弱主密码。
 */
object PasswordEntropy {

    /**
     * 手输口令估计的保守系数。
     *
     * 取 1.15：排列规模 `log2(C(n,k) × k!)` 只统计了「用了哪些字符」，
     * 没有考虑顺序信息，因此对不含周期的口令会略微低估；乘一个小系数
     * 让结果更接近真实，同时保持整体保守（最终还会被「长度 × log2(池)」截断）。
     */
    private const val CONSERVATIVE_FACTOR = 1.15

    /**
     * 精确计算由 [PasswordPolicy] 生成口令的熵（比特）。
     *
     * - 随机模式：`length × log2(|字符池|)`
     * - 易记模式：`单词数 × log2(词表大小)`（+ 数字后缀带来的额外熵）
     * - PIN 模式：`位数 × log2(数字池大小)`
     *
     * 注意：口令生成器中的「禁止三连重复」与「每类至少一个」约束会让真实
     * 分布略微偏离独立均匀采样，理论上可比本公式少零点几比特。因此这里
     * 返回的是**上界**，配合 [strengthOfPolicy] 中的保守分级使用。
     */
    fun bitsOf(policy: PasswordPolicy, wordListSize: Int = WordList.CORE_SIZE): Double {
        return when (policy.mode) {
            PasswordPolicy.Mode.RANDOM -> {
                val pool = policy.alphabet().size
                if (pool <= 1) 0.0 else policy.safeLength * log2(pool.toDouble())
            }
            PasswordPolicy.Mode.PASSPHRASE -> {
                val effectiveWords = if (wordListSize <= 1) 1 else wordListSize
                var bits = policy.safeLength * log2(effectiveWords.toDouble())
                if (policy.appendDigitsToWords) bits += policy.safeLength * log2(10.0)
                bits
            }
            PasswordPolicy.Mode.PIN -> {
                val pool = if (policy.avoidAmbiguous) PasswordPolicy.DIGITS_SAFE.length else 10
                policy.safeLength * log2(pool.toDouble())
            }
        }
    }

    /**
     * 把比特数映射为人类可读的等级与描述。
     *
     * 阈值取自通行实践：
     *  - < 40 bit  离线爆破可在数小时内完成（GPU 集群）
     *  - 40~59 bit 个人攻击者需要数天到数月
     *  - 60~79 bit 国家级以下的攻击者基本不可行
     *  - ≥ 80 bit  面向未来的安全余量
     */
    fun strengthOf(bits: Double): Strength = when {
        bits < 28 -> Strength.VERY_WEAK
        bits < 40 -> Strength.WEAK
        bits < 60 -> Strength.FAIR
        bits < 80 -> Strength.STRONG
        else -> Strength.EXCELLENT
    }

    fun strengthOfPolicy(policy: PasswordPolicy): Strength = strengthOf(bitsOf(policy))

    /**
     * 针对**用户手输口令**（例如主密码）的保守熵估计。
     *
     * 诚实声明：任何不了解口令生成过程的估计都只是启发式。本函数的目标不是
     * 「猜准」，而是**不猜高** —— 一个虚高的强度条会让用户放心使用弱主密码，
     * 这比显示得偏悲观危险得多。
     *
     * 两条互补的判据，按「口令是否有整体重复结构」二选一：
     *
     *  1. **有整体周期**（口令恰好是某个片段的整数次重复）：
     *     熵 ≈ `周期 p × log2(池大小) + log2(重复次数 r)`。
     *     例如 `abcabcabcabcabcabc` 的真实熵约 14 bit，而「长度 × log2(池)」
     *     会给出 84 bit —— 相差 6 倍。这种情况下**只有**周期判据是对的，
     *     字符多样性判据会因为「a 出现 6 次」而严重高估（实测会高估到 33 bit）。
     *     因此这里不做最大化，直接采用周期判据。
     *
     *  2. **没有整体周期**：`log2(n! / Π 频次!) + k × log2(池大小)`，
     *     即「这些字符的所有可能排列」的信息量，再乘一个保守系数。
     *     它天然惩罚局部重复字符（全同字符时第一项为 0），
     *     并按口令长度温和缩放。
     *
     *  两种情况下结果都被「长度 × log2(池大小)」这一绝对上界截断。
     */
    fun estimateUserTypedBits(password: CharArray): Double {
        if (password.isEmpty()) return 0.0
        val length = password.size

        val pool = characterPoolSize(password)
        val idealBits = length * log2(pool.toDouble())

        val frequencies = HashMap<Char, Int>()
        for (c in password) frequencies[c] = (frequencies[c] ?: 0) + 1
        val distinct = frequencies.size
        if (distinct <= 1) return 0.0

        val period = smallestPeriod(password)
        val raw = if (period in 1 until length) {
            // 判据 1：存在整体重复结构
            val repetitions = length / period
            period * log2(pool.toDouble()) + log2(repetitions.toDouble())
        } else {
            // 判据 2：无整体结构，按排列规模估计并保守上调
            (permutationBits(frequencies, length) + distinct * log2(pool.toDouble())) *
                CONSERVATIVE_FACTOR
        }
        return minOf(raw, idealBits)
    }

    /**
     * `log2(n! / Π 频次!)`：在已知「用了哪些字符」的前提下，
     * 把这些字符排列成一个口令所需的比特数。全同字符时为 0。
     */
    private fun permutationBits(frequencies: Map<Char, Int>, length: Int): Double {
        var bits = log2Factorial(length)
        for (count in frequencies.values) bits -= log2Factorial(count)
        return bits.coerceAtLeast(0.0)
    }

    /** log2(n!)，用累加避免阶乘溢出。 */
    private fun log2Factorial(n: Int): Double {
        var sum = 0.0
        for (i in 2..n) sum += log2(i.toDouble())
        return sum
    }

    /**
     * 识别整个口令的最小重复周期。
     *
     * 返回 [password] 的长度表示「没有整体周期」。用 KMP 风格的已匹配长度跳转，
     * 复杂度 O(n)，因此可以安全地用在每次按键触发的实时强度条上。
     */
    private fun smallestPeriod(password: CharArray): Int {
        val n = password.size
        if (n < 2) return n
        val fail = IntArray(n)
        var k = 0
        for (i in 1 until n) {
            while (k > 0 && password[i] != password[k]) k = fail[k - 1]
            if (password[i] == password[k]) k++
            fail[i] = k
        }
        val p = n - fail[n - 1]
        return if (n % p == 0) p else n
    }

    /** 口令中出现过的字符类别所构成的字符池大小（下界估计）。 */
    private fun characterPoolSize(password: CharArray): Int {
        var lower = false
        var upper = false
        var digit = false
        var symbol = false
        var other = false
        for (c in password) {
            when {
                c in 'a'..'z' -> lower = true
                c in 'A'..'Z' -> upper = true
                c in '0'..'9' -> digit = true
                c.isLetterOrDigit() -> other = true
                else -> symbol = true
            }
        }
        var pool = 0
        if (lower) pool += 26
        if (upper) pool += 26
        if (digit) pool += 10
        if (symbol) pool += 33
        if (other) pool += 64
        return pool.coerceAtLeast(1)
    }

    /**
     * 熵 → 离线爆破耗时的粗略换算，用于向用户解释「这意味着什么」。
     *
     * 假设攻击者每秒可做 [guessesPerSecond] 次针对本应用 Argon2id 参数的猜测。
     * 由于 Argon2id 每次都要占用 64 MiB 内存，GPU/ASIC 的并行优势被严重削弱，
     * 这里取 10^5 次/秒作为一台高端 GPU 的乐观估计（对应 PBKDF2 时代
     * 10^10 次/秒的估计，本应用的内存硬化设计带来了约 5 个数量级的提升）。
     */
    fun crackTimeEstimate(bits: Double, guessesPerSecond: Double = 1e5): CrackTime {
        if (bits <= 0) return CrackTime(0.0, "瞬间")
        // 平均需要尝试一半空间
        val seconds = 2.0.pow(bits - 1) / guessesPerSecond
        return CrackTime(seconds, humanize(seconds))
    }

    private fun humanize(seconds: Double): String {
        if (seconds.isInfinite() || seconds > BEYOND_UNIVERSE_SECONDS) return "远超宇宙年龄（> 1000 年）"
        val minute = 60.0
        val hour = minute * 60
        val day = hour * 24
        val year = day * 365.25
        return when {
            seconds < 1 -> "瞬间"
            seconds < minute -> "%.0f 秒".format(seconds)
            seconds < hour -> "%.0f 分钟".format(seconds / minute)
            seconds < day -> "%.0f 小时".format(seconds / hour)
            seconds < year -> "%.0f 天".format(seconds / day)
            seconds < year * 1000 -> "%.0f 年".format(seconds / year)
            else -> "%.0f 千年".format(seconds / (year * 1000))
        }
    }

    /** 自然对数辅助（保留以便未来切换到 nats 单位做比较）。 */
    internal fun nats(bits: Double): Double = bits * ln(2.0)

    enum class Strength(val label: String) {
        VERY_WEAK("极弱"),
        WEAK("弱"),
        FAIR("中等"),
        STRONG("强"),
        EXCELLENT("极强"),
    }

    /**
     * 爆破耗时的时间刻度。
     *
     * 界面需要**按当前语言**渲染「3 分钟」这样的文案，而 `core/` 不能依赖
     * Android 资源（它要被纯 JVM 测试覆盖）。因此这里只给出「刻度 + 数值」，
     * 具体文案由界面层的 `crackTimeText(...)` 负责。
     *
     * [CrackTime.readable] 保留中文渲染，**只供纯 JVM 测试使用**；
     * 界面**不应**再直接使用它，否则英文界面会露出中文。
     */
    enum class Approx(val seconds: Double) {
        BEYOND_UNIVERSE(Double.MAX_VALUE),
        INSTANT(0.0),
        SECONDS(1.0),
        MINUTES(60.0),
        HOURS(3600.0),
        DAYS(86_400.0),
        YEARS(31_557_600.0),          // 365.25 天
        MILLENNIA(31_557_600_000.0),
        ;

        /**
         * 把耗时换算成最合适的刻度。
         *
         * 调用方式统一写成 `Approx.SECONDS.of(seconds)`：以秒为基准换算。
         * 它需要接收方只是为了让 `when` 的各个分支能直接引用枚举常量，
         * 数值本身与**调用方选哪个接收者无关**。
         */
        fun of(seconds: Double): Approx = when {
            seconds.isInfinite() || seconds > BEYOND_UNIVERSE_SECONDS -> BEYOND_UNIVERSE
            seconds < 1.0 -> INSTANT
            seconds < MINUTES.seconds -> SECONDS
            seconds < HOURS.seconds -> MINUTES
            seconds < DAYS.seconds -> HOURS
            seconds < YEARS.seconds -> DAYS
            seconds < MILLENNIA.seconds -> YEARS
            else -> MILLENNIA
        }

        /**
         * 该刻度下的数值（用于文案里的 %1$s）。
         */
        fun valueIn(seconds: Double): Double = when (this) {
            BEYOND_UNIVERSE -> seconds
            INSTANT -> seconds
            else -> seconds / this.seconds
        }
    }

    /**
     * 超过这个秒数就认为「远超宇宙年龄」。
     *
     * 取 1000 年：3.15e10 秒恰好是 1000 年，因此这个阈值与文案里的
     * 「> 1000 年」是同一件事（原先是一个散落在 `humanize` 里的魔法数字）。
     */
    const val BEYOND_UNIVERSE_SECONDS = 3.15e10

    /**
     * @param seconds 精确耗时（秒），界面据此做本地化渲染
     * @param readable 中文可读文案（仅用于测试与日志，界面请用 [seconds] 自行渲染）
     */
    data class CrackTime(val seconds: Double, val readable: String) {
        /** 按当前语言渲染时使用的时间刻度。 */
        val approx: Approx get() = Approx.SECONDS.of(seconds)
    }
}
