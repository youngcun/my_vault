package com.myvault.password.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 熵评估测试。
 *
 * 这些断言把「熵的解析公式」钉死在测试里。任何人若改动生成逻辑却忘了
 * 同步更新熵公式，测试会立刻失败 —— 这防止出现「界面显示 100 bit，
 * 实际只有 40 bit」这种最危险的安全谎言。
 */
class PasswordEntropyTest {

    @Test
    fun `随机模式熵等于长度乘以字符池对数`() {
        // 26 个小写字母 → log2(26) = 4.7004...
        val policy = PasswordPolicy(
            length = 10,
            useLowercase = true,
            useUppercase = false,
            useDigits = false,
            useSymbols = false,
            requireEachClass = false,
        )
        assertEquals(10 * 4.700439718, PasswordEntropy.bitsOf(policy), 1e-6)
    }

    @Test
    fun `全字符集 20 位口令熵超过 128 bit`() {
        val policy = PasswordPolicy(length = 20)
        // 94 个可打印 ASCII 字符 → 20 × 6.5546 = 131.1
        val bits = PasswordEntropy.bitsOf(policy)
        assertTrue("实际 $bits", bits > 128.0)
        assertEquals(PasswordEntropy.Strength.EXCELLENT, PasswordEntropy.strengthOf(bits))
    }

    @Test
    fun `易记口令熵按词表大小计算`() {
        val policy = PasswordPolicy(mode = PasswordPolicy.Mode.PASSPHRASE, length = 6, capitalizeWords = false)
        val bits = PasswordEntropy.bitsOf(policy, wordListSize = 2048)
        // 6 × 11 = 66 bit
        assertEquals(66.0, bits, 1e-9)
        assertEquals(PasswordEntropy.Strength.STRONG, PasswordEntropy.strengthOf(bits))
    }

    @Test
    fun `扩展词表带来额外熵`() {
        val core = PasswordPolicy(mode = PasswordPolicy.Mode.PASSPHRASE, length = 5)
        val ext = core.copy(wordListSize = WordList.EXTENDED_SIZE)
        assertTrue(
            PasswordEntropy.bitsOf(ext, WordList.EXTENDED_SIZE) >
                PasswordEntropy.bitsOf(core, WordList.CORE_SIZE),
        )
    }

    @Test
    fun `PIN 模式熵很低并被评为弱`() {
        val policy = PasswordPolicy(mode = PasswordPolicy.Mode.PIN, length = 6)
        val bits = PasswordEntropy.bitsOf(policy)
        assertEquals(6 * 3.321928094887362, bits, 1e-9)   // ≈ 19.9 bit
        assertEquals(PasswordEntropy.Strength.VERY_WEAK, PasswordEntropy.strengthOf(bits))
    }

    @Test
    fun `强度分级在阈值处边界正确`() {
        assertEquals(PasswordEntropy.Strength.VERY_WEAK, PasswordEntropy.strengthOf(27.9))
        assertEquals(PasswordEntropy.Strength.WEAK, PasswordEntropy.strengthOf(28.0))
        assertEquals(PasswordEntropy.Strength.WEAK, PasswordEntropy.strengthOf(39.9))
        assertEquals(PasswordEntropy.Strength.FAIR, PasswordEntropy.strengthOf(40.0))
        assertEquals(PasswordEntropy.Strength.FAIR, PasswordEntropy.strengthOf(59.9))
        assertEquals(PasswordEntropy.Strength.STRONG, PasswordEntropy.strengthOf(60.0))
        assertEquals(PasswordEntropy.Strength.EXCELLENT, PasswordEntropy.strengthOf(80.0))
    }

    @Test
    fun `短密码被正确评为极弱`() {
        val bits = PasswordEntropy.estimateUserTypedBits("123456".toCharArray())
        assertTrue("实际 $bits bit", bits < 28.0)
        assertEquals(PasswordEntropy.Strength.VERY_WEAK, PasswordEntropy.strengthOf(bits))
    }

    @Test
    fun `重复模式的口令被大幅折减`() {
        // "abcabcabcabcabcabc" 由周期 3 的片段重复 6 次而成：
        // 真实熵 ≈ log2(26^3 × 6) ≈ 16.7 bit，而不是 18 × log2(26) ≈ 84.6 bit。
        // 这是本应用最重要的保守性保证之一：绝不能把「重复三字母」显示成「强」。
        val repeated = PasswordEntropy.estimateUserTypedBits("abcabcabcabcabcabc".toCharArray())
        val distinct = PasswordEntropy.estimateUserTypedBits("qwertyuiopasdfghjk".toCharArray())
        assertTrue(
            "重复口令估计应远低于等长随机口令（repeated=$repeated distinct=$distinct）",
            repeated < distinct * 0.5,
        )
        assertTrue("重复口令不应被高估到 30 bit 以上（实际 $repeated）", repeated < 30.0)
        assertTrue("重复口令也不应被估得过低（实际 $repeated）", repeated > 10.0)
        assertEquals(PasswordEntropy.Strength.VERY_WEAK, PasswordEntropy.strengthOf(repeated))
    }

    @Test
    fun `周期性口令的熵由周期长度决定`() {
        // 周期 2 重复 9 次：真实熵 ≈ log2(26^2 × 9) ≈ 12.6 bit
        val period2 = PasswordEntropy.estimateUserTypedBits("ababababababababab".toCharArray())
        // 周期 6 重复 3 次：真实熵 ≈ log2(26^6 × 3) ≈ 29.8 bit
        val period6 = PasswordEntropy.estimateUserTypedBits("abcdefabcdefabcdef".toCharArray())
        assertTrue("周期越长熵越高（period2=$period2 period6=$period6）", period6 > period2)
        assertTrue("周期 2 的重复几乎是零熵（实际 $period2）", period2 < 15.0)
        assertEquals(
            "周期 2 的重复必须被判为极弱",
            PasswordEntropy.Strength.VERY_WEAK,
            PasswordEntropy.strengthOf(period2),
        )
    }

    @Test
    fun `重复拼接几乎不增加估算强度`() {
        // 重要且反直觉：长度翻倍但内容是原样重复，真实熵几乎没变。
        // 若这里给出「翻倍」的强度，用户就会以为复制一遍等于强一倍。
        val single = PasswordEntropy.estimateUserTypedBits("Xk9#mQ2v".toCharArray())
        val doubled = PasswordEntropy.estimateUserTypedBits("Xk9#mQ2vXk9#mQ2v".toCharArray())
        assertTrue(
            "重复拼接不应显著提升强度（single=$single doubled=$doubled）",
            doubled < single * 1.25,
        )
        assertTrue("更长的串也不应被估得更弱", doubled >= single * 0.9)
    }

    @Test
    fun `熵估计永不高于长度乘字符池这一绝对上界`() {
        val cases = listOf(
            "a", "abc", "password", "Password1", "Xk9#mQ2v",
            "abcabcabcabcabcabc", "aaaaaaaaaaaaaaaa", "qwertyuiopasdfghjk",
            "correct horse battery staple",
        )
        for (c in cases) {
            val chars = c.toCharArray()
            val bits = PasswordEntropy.estimateUserTypedBits(chars)
            // 用 95 个可打印 ASCII 字符作为理论最大池
            val hardUpperBound = chars.size * kotlin.math.log2(95.0)
            assertTrue(
                "「$c」的估计 $bits 超过了绝对上界 $hardUpperBound",
                bits <= hardUpperBound + 1e-9,
            )
            assertTrue("熵不能为负：$c -> $bits", bits >= 0.0)
        }
    }

    @Test
    fun `空口令熵为零且不被高估`() {
        assertEquals(0.0, PasswordEntropy.estimateUserTypedBits(CharArray(0)), 1e-12)
        assertEquals(PasswordEntropy.Strength.VERY_WEAK, PasswordEntropy.strengthOf(0.0))
    }

    @Test
    fun `爆破耗时换算对小熵给出可读的短时间`() {
        val tiny = PasswordEntropy.crackTimeEstimate(20.0)
        assertTrue(tiny.readable, tiny.readable.isNotEmpty())
        assertTrue("20 bit 应当是级别很低的耗时，实际 ${tiny.readable}", tiny.seconds < 60)
    }

    @Test
    fun `爆破耗时换算对大熵给出不可行的结论`() {
        val strong = PasswordEntropy.crackTimeEstimate(128.0)
        assertTrue(
            "128 bit 应远超宇宙年龄，实际 ${strong.readable}",
            strong.readable.contains("宇宙年龄") || strong.seconds > 3.0e10,
        )
    }
}
