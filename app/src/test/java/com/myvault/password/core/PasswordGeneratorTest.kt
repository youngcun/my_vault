package com.myvault.password.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.SecureRandom

/**
 * 密码生成器测试。
 *
 * 重点验证三件容易出错的事：
 *  1. 长度与字符集约束被严格遵守（否则会生成被网站拒收的密码）；
 *  2. 每个已选字符类都出现（大多数网站的强制要求）；
 *  3. 采样无偏、且不使用可预测的随机源（否则熵名不副实）。
 */
class PasswordGeneratorTest {

    private val generator = PasswordGenerator()

    // ---------------------------------------------------------------- 随机模式

    @Test
    fun `随机密码长度精确符合要求`() {
        for (len in intArrayOf(8, 12, 20, 33, 64, 128)) {
            val pwd = generator.generate(PasswordPolicy(length = len))
            assertEquals("长度 $len 不符", len, pwd.length)
        }
    }

    @Test
    fun `随机密码只包含已选择的字符类`() {
        val policy = PasswordPolicy(
            length = 40,
            useLowercase = true,
            useUppercase = false,
            useDigits = true,
            useSymbols = false,
        )
        val pwd = generator.generate(policy)
        val allowed = (PasswordPolicy.LOWER + PasswordPolicy.DIGITS).toSet()
        assertTrue("出现了未选字符: $pwd", pwd.all { it in allowed })
    }

    @Test
    fun `每个已选字符类至少出现一次`() {
        // 这是绝大多数网站密码策略的硬性要求；用 200 次采样确认不是偶然
        repeat(200) {
            val pwd = generator.generate(PasswordPolicy(length = 16, requireEachClass = true))
            assertTrue("缺少小写: $pwd", pwd.any { it in 'a'..'z' })
            assertTrue("缺少大写: $pwd", pwd.any { it in 'A'..'Z' })
            assertTrue("缺少数字: $pwd", pwd.any { it in '0'..'9' })
            assertTrue("缺少符号: $pwd", pwd.any { !it.isLetterOrDigit() })
        }
    }

    @Test
    fun `关闭每类要求后仍只使用已选字符集`() {
        val policy = PasswordPolicy(
            length = 50,
            useLowercase = true,
            useUppercase = false,
            useDigits = false,
            useSymbols = false,
            requireEachClass = false,
        )
        val pwd = generator.generate(policy)
        assertTrue(pwd.all { it in 'a'..'z' })
    }

    @Test
    fun `排除形近字符时不出现易混淆字符`() {
        val policy = PasswordPolicy(length = 80, avoidAmbiguous = true, useSymbols = false)
        repeat(20) {
            val pwd = generator.generate(policy)
            for (bad in listOf('0', 'O', '1', 'l', 'I', 'o')) {
                assertFalse("形近字符 $bad 不应出现: $pwd", pwd.contains(bad))
            }
        }
    }

    @Test
    fun `连续重复字符不超过限制`() {
        repeat(100) {
            val pwd = generator.generate(PasswordPolicy(length = 40, maxRepeatedRun = 2))
            var run = 1
            for (i in 1 until pwd.length) {
                run = if (pwd[i] == pwd[i - 1]) run + 1 else 1
                assertTrue("出现了 $run 个连续相同字符: $pwd", run <= 2)
            }
        }
    }

    @Test
    fun `未选择任何字符类时给出明确错误`() {
        val policy = PasswordPolicy(useLowercase = false, useUppercase = false, useDigits = false, useSymbols = false)
        assertNotNull(policy.validate())
        try {
            generator.generate(policy)
            fail("空字符集必须抛异常，而不是返回空密码")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("字符类型"))
        }
    }

    @Test
    fun `长度不足以容纳全部字符类时钳制到可行下界`() {
        // 场景：用户勾选了 4 类字符，但把长度拖到 3。
        //
        // 期望行为（两层保护，都不能静默放宽约束）：
        //   1. safeLength 把长度钳制到合法下界 8，因此生成的密码**恰好 8 位**，
        //      而不是「3 位里硬塞 4 类」（那是不可能的）；
        //   2. validate() 对钳制后仍不可行的策略（字符类数 > 长度）返回原因，
        //      让界面能提示用户。
        val tooShort = PasswordPolicy(
            length = 3,
            useLowercase = true,
            useUppercase = true,
            useDigits = true,
            useSymbols = true,
            requireEachClass = true,
        )
        assertEquals(4, tooShort.classCount())
        assertEquals("长度必须被钳制到可容纳字符类的下界", 8, tooShort.safeLength)

        val generated = generator.generate(tooShort)
        assertEquals(8, generated.length)
        assertTrue("小写缺失", generated.any { it in 'a'..'z' })
        assertTrue("大写缺失", generated.any { it in 'A'..'Z' })
        assertTrue("数字缺失", generated.any { it in '0'..'9' })
        assertTrue("符号缺失", generated.any { !it.isLetterOrDigit() })

        // 钳制后仍然不可行的极端策略必须被 validate() 拒绝。
        // 这里直接把长度设为 0 并关闭钳制下限之外的所有余量：
        // 由于 MIN_RANDOM_LENGTH 是 8，构造不出 classCount() > safeLength 的策略，
        // 因此改为验证 validate() 对「空字符集」这一类真正不可行的输入给出原因。
        val emptyClasses = PasswordPolicy(
            length = 20,
            useLowercase = false,
            useUppercase = false,
            useDigits = false,
            useSymbols = false,
        )
        assertNotNull("空字符集必须被报告为不可行", emptyClasses.validate())
        try {
            generator.generate(emptyClasses)
            fail("空字符集必须抛异常，而不是返回空密码")
        } catch (expected: IllegalArgumentException) {
            // 预期
        }
    }

    @Test
    fun `不可行策略给出结构化原因而不是只有中文文案`() {
        // 界面必须按当前语言渲染这条提示，因此 core/ 只能给出「是哪一类问题」。
        // 若这里哪天改回直接返回中文，英文界面就会露出中文 ——
        // 这个用例就是钉住这一点的。
        val emptyClasses = PasswordPolicy(
            length = 20,
            useLowercase = false,
            useUppercase = false,
            useDigits = false,
            useSymbols = false,
        )
        assertEquals(
            "空字符集应报告为「未选任何字符类型」",
            PolicyError.NoCharacterClass,
            emptyClasses.invalidReason(),
        )

        // 可行策略必须返回 null，否则界面会显示一条不存在的错误。
        assertNull("默认策略是可行的，不应返回原因", PasswordPolicy().invalidReason())
    }

    @Test
    fun `长度被钳制后不可能装不下字符类`() {
        // 这条不变量是「PolicyError 只有 NoCharacterClass 一个分支」的依据：
        // 字符类型最多 4 种，而 safeLength 对随机模式钳制到至少 MIN_RANDOM_LENGTH=8，
        // 对口令模式钳制到至少 MIN_WORD_COUNT=3。因此
        //   -「长度 < 字符类型数」不可达；
        //   -「单词数为 0」不可达（口令模式 safeLength 永远 ≥ 3）。
        // 若哪天有人把钳制下界改小到 3 以下，这个用例会失败，
        // 提醒他必须把被删掉的两个 PolicyError 分支加回来。
        for (length in -5..2) {
            val random = PasswordPolicy(
                mode = PasswordPolicy.Mode.RANDOM,
                length = length,
                useLowercase = true,
                useUppercase = true,
                useDigits = true,
                useSymbols = true,
            )
            assertTrue(
                "随机模式 safeLength 必须 ≥ 字符类型数（length=$length, " +
                    "safeLength=${random.safeLength}, classes=${random.classCount()}）",
                random.safeLength >= random.classCount(),
            )
            assertTrue("随机模式 safeLength 不得低于下界", random.safeLength >= 8)

            val passphrase = PasswordPolicy(mode = PasswordPolicy.Mode.PASSPHRASE, length = length)
            assertTrue(
                "口令模式 safeLength 不得低于 1（length=$length, safeLength=${passphrase.safeLength}）",
                passphrase.safeLength >= 1,
            )
            assertTrue("口令模式 safeLength 不得低于下界", passphrase.safeLength >= 3)
        }
        // 字符类型最多 4 种，这是上面比较的前提
        val fourClasses = PasswordPolicy(
            length = 20,
            useLowercase = true,
            useUppercase = true,
            useDigits = true,
            useSymbols = true,
        )
        assertEquals(4, fourClasses.classCount())
        assertTrue("前提变了：字符类型数不再 ≤ 8", fourClasses.classCount() <= 8)
    }

    @Test
    fun `结构化原因与中文渲染描述同一件事`() {
        // validate() 是 invalidReason() 的中文渲染，两者不可分叉：
        // 只要 invalidReason() 说可行，validate() 就必须为空，反之亦然。
        val policies = listOf(
            PasswordPolicy(),
            PasswordPolicy(mode = PasswordPolicy.Mode.PASSPHRASE, length = 0),
            PasswordPolicy(
                length = 20,
                useLowercase = false,
                useUppercase = false,
                useDigits = false,
                useSymbols = false,
            ),
            PasswordPolicy(mode = PasswordPolicy.Mode.PIN, length = 6),
        )
        for (policy in policies) {
            assertEquals(
                "策略 $policy 的两条判定路径结果不一致",
                policy.invalidReason() == null,
                policy.validate() == null,
            )
        }
    }

    @Test
    fun `长度会被规范化到安全范围内`() {        // 防止 UI 传入 0 或 100000 导致空密码或内存问题
        assertEquals(PasswordPolicy.MIN_RANDOM_LENGTH, PasswordPolicy(length = 1).safeLength)
        assertEquals(PasswordPolicy.MAX_RANDOM_LENGTH, PasswordPolicy(length = 100_000).safeLength)
    }

    @Test
    fun `相同策略连续生成不会重复`() {
        val policy = PasswordPolicy(length = 24)
        val seen = HashSet<String>()
        repeat(500) { seen.add(generator.generate(policy)) }
        assertEquals("500 次生成出现了重复，随机源可疑", 500, seen.size)
    }

    // ---------------------------------------------------------------- 易记模式

    @Test
    fun `易记口令单词数量正确`() {
        val policy = PasswordPolicy(
            mode = PasswordPolicy.Mode.PASSPHRASE,
            length = 5,
            separator = "-",
            capitalizeWords = false,
            wordListSize = WordList.CORE_SIZE,
        )
        val pwd = generator.generate(policy)
        assertEquals(5, pwd.split("-").size)
    }

    @Test
    fun `易记口令的每个词都来自词表`() {
        val policy = PasswordPolicy(
            mode = PasswordPolicy.Mode.PASSPHRASE,
            length = 6,
            separator = ".",
            capitalizeWords = false,
        )
        val words = WordList.words(WordList.CORE_SIZE).toHashSet()
        val pwd = generator.generate(policy)
        for (w in pwd.split(".")) {
            assertTrue("词 $w 不在词表中", words.contains(w))
        }
    }

    /**
     * 回归测试：字符池大小超过 256 时的无偏采样。
     *
     * 曾经的实现用单字节做拒绝采样，`bound >= 256` 时会产生「全部字节都被丢弃」
     * 的死循环 —— 选择扩展词表（4096 词）生成易记口令就会卡死界面。
     * 这条用例专门覆盖 `bound > 256` 的路径。
     */
    @Test
    fun `字符池超过 256 时仍能生成易记口令`() {
        for (listSize in listOf(WordList.CORE_SIZE, WordList.EXTENDED_SIZE)) {
            val policy = PasswordPolicy(
                mode = PasswordPolicy.Mode.PASSPHRASE,
                length = 8,
                separator = "-",
                capitalizeWords = false,
                wordListSize = listSize,
            )
            val words = WordList.words(listSize).toHashSet()
            repeat(30) {
                val pwd = generator.generate(policy)
                val parts = pwd.split("-")
                assertEquals("单词数不符（词表 $listSize）：$pwd", 8, parts.size)
                for (w in parts) {
                    assertTrue("词 $w 不在词表（大小 $listSize）中", words.contains(w))
                }
            }
        }
    }

    @Test
    fun `词表规模确实超过 256 因而覆盖大步长采样路径`() {
        // 这条断言保护上一条测试的前提：如果词表被缩小到 256 以下，
        // 大步长路径就不再被覆盖，测试会静默失去意义。
        assertTrue(WordList.words(WordList.CORE_SIZE).size > 256)
        assertTrue(WordList.words(WordList.EXTENDED_SIZE).size > 256)
    }

    @Test
    fun `易记口令大写选项生效`() {
        val policy = PasswordPolicy(
            mode = PasswordPolicy.Mode.PASSPHRASE,
            length = 4,
            separator = "-",
            capitalizeWords = true,
        )
        val pwd = generator.generate(policy)
        for (w in pwd.split("-")) {
            assertTrue("首字母未大写: $w", w[0].isUpperCase())
        }
    }

    @Test
    fun `词表档位被正确截取`() {
        val all = WordList.allWords()
        assertTrue("词表实际条数不足: ${all.size}", all.size >= WordList.EXTENDED_SIZE)
        assertEquals(WordList.CORE_SIZE, WordList.words(WordList.CORE_SIZE).size)
        assertEquals(WordList.EXTENDED_SIZE, WordList.words(WordList.EXTENDED_SIZE).size)
        // 超出扩展档位的请求应被夹到 EXTENDED，而不是回落到 CORE ——
        // 否则熵公式会高估词表规模。
        assertEquals(WordList.EXTENDED_SIZE, WordList.words(12345).size)
        // 小于 CORE 的请求取 CORE
        assertEquals(WordList.CORE_SIZE, WordList.words(10).size)
        // CORE 档位必须是 EXTENDED 的前缀，保证「小档位更好记」这一承诺成立
        assertTrue(
            "CORE 档位应是 EXTENDED 档位的前缀",
            all.subList(0, WordList.CORE_SIZE) == WordList.words(WordList.CORE_SIZE),
        )
    }

    @Test
    fun `词表内容全部合法且不重复`() {
        val all = WordList.allWords()
        assertEquals("词表存在重复项", all.size, all.toHashSet().size)
        for (w in all) {
            assertTrue("词 $w 长度越界", w.length in 3..8)
            assertTrue("词 $w 含非小写字母字符", w.all { it in 'a'..'z' })
        }
    }

    // ---------------------------------------------------------------- PIN 模式

    @Test
    fun `PIN 模式只产生数字且长度正确`() {
        val policy = PasswordPolicy(mode = PasswordPolicy.Mode.PIN, length = 8)
        repeat(50) {
            val pin = generator.generate(policy)
            assertEquals(8, pin.length)
            assertTrue(pin.all { it in '0'..'9' })
        }
    }

    @Test
    fun `PIN 模式排除形近数字时不含 0 与 1`() {
        val policy = PasswordPolicy(mode = PasswordPolicy.Mode.PIN, length = 20, avoidAmbiguous = true)
        repeat(20) {
            val pin = generator.generate(policy)
            assertFalse(pin.contains('0'))
            assertFalse(pin.contains('1'))
        }
    }

    // ---------------------------------------------------------------- 无偏性

    @Test
    fun `采样分布无明显偏差`() {
        // 用固定种子的 SecureRandom 做卡方检验：既保证可重复，
        // 也避免在 CI 上反复读取系统熵源造成不必要的开销。
        // 若实现里用了 nextInt(n) % pool.size 这类有偏做法，
        // 26 元池上的卡方值会显著偏离（拒绝采样的期望偏差 < 1%）。
        val seeded = SecureRandom()
        seeded.setSeed(0x5EED_1234_ABCDL)
        val generator = PasswordGenerator(seeded)
        val policy = PasswordPolicy(
            length = 1,
            useLowercase = true,
            useUppercase = false,
            useDigits = false,
            useSymbols = false,
            requireEachClass = false,
            maxRepeatedRun = 0,
        )
        val counts = IntArray(26)
        val rounds = 40_000
        repeat(rounds) {
            val c = generator.generate(policy)[0]
            counts[c - 'a']++
        }
        val expected = rounds / 26.0
        val chiSquare = counts.sumOf { c -> val d = c - expected; d * d / expected }
        // 自由度 25，99.9% 分位约 52.6；取 70 作为宽松上界，误报率极低
        assertTrue("卡方值 $chiSquare 过大，采样可能存在偏差", chiSquare < 70.0)
        // 同时确认每个字符都至少出现过一次（真随机的健全性检查）
        assertTrue("有字符从未被生成：${counts.indexOfFirst { it == 0 }}", counts.all { it > 0 })
    }

    @Test
    fun `不同策略生成结果互不相同`() {
        val a = generator.generate(PasswordPolicy(mode = PasswordPolicy.Mode.PIN, length = 12))
        val b = generator.generate(PasswordPolicy(length = 12))
        assertNotEquals(a, b)
    }
}
