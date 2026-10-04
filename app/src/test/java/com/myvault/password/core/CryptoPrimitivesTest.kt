package com.myvault.password.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * 加密原语测试。
 *
 * 这些测试是「自证安全」的一部分：它们可以在任意机器上离线重跑，
 * 证明加密实现满足其声明的性质（尤其是篡改必然被发现）。
 */
class CryptoPrimitivesTest {

    private val key = ByteArray(32) { it.toByte() }

    @Test
    fun `AES-GCM 往返还原明文`() {
        val plaintext = "correct horse battery staple 中文 🔐".toByteArray(Charsets.UTF_8)
        val ct = CryptoPrimitives.aesGcmEncrypt(key, plaintext)
        val pt = CryptoPrimitives.aesGcmDecrypt(key, ct)
        assertArrayEquals(plaintext, pt)
    }

    /**
     * 回归测试：**空明文必须能往返**。
     *
     * 空明文的密文恰好是 `IV(12) + Tag(16) = 28` 字节。
     * 曾经的校验写成 `size > 28`（应为 `>=`），导致所有留空字段
     * （未填用户名 / 网址 / 备注）在读取时抛「密文长度不合法」。
     * 上层容错逻辑会静默跳过该条目，用户看到的现象就是
     * **「新建条目保存不了、也不报错」**。
     *
     * 这是一个只在设备上才暴露的缺陷：写入成功、只有读回时才失败。
     */
    @Test
    fun `空明文可以正常往返（回归 保存后读不回）`() {
        val ct = CryptoPrimitives.aesGcmEncrypt(key, ByteArray(0))
        assertEquals(
            "空明文的密文应恰好是 IV + Tag",
            CryptoPrimitives.MIN_CIPHERTEXT_BYTES,
            ct.size,
        )
        val pt = CryptoPrimitives.aesGcmDecrypt(key, ct)
        assertEquals(0, pt.size)
    }

    @Test
    fun `单字节与短明文都能往返`() {
        for (size in 1..8) {
            val plaintext = ByteArray(size) { it.toByte() }
            val ct = CryptoPrimitives.aesGcmEncrypt(key, plaintext)
            assertArrayEquals(
                "长度 $size 的明文往返失败",
                plaintext,
                CryptoPrimitives.aesGcmDecrypt(key, ct),
            )
        }
    }

    @Test
    fun `长度不足的密文被明确拒绝而不是崩溃`() {
        for (badSize in 0 until CryptoPrimitives.MIN_CIPHERTEXT_BYTES) {
            try {
                CryptoPrimitives.aesGcmDecrypt(key, ByteArray(badSize))
                fail("长度 $badSize 的密文必须被拒绝")
            } catch (expected: IllegalArgumentException) {
                // 预期
            }
        }
    }

    @Test
    fun `空明文与带 AAD 的场景同样可往返`() {
        val aad = "field:username|entry:1".toByteArray()
        val ct = CryptoPrimitives.aesGcmEncrypt(key, ByteArray(0), aad)
        assertEquals(CryptoPrimitives.MIN_CIPHERTEXT_BYTES, ct.size)
        assertEquals(0, CryptoPrimitives.aesGcmDecrypt(key, ct, aad).size)
        // AAD 不匹配时仍然必须失败（空明文同样受认证保护）
        try {
            CryptoPrimitives.aesGcmDecrypt(key, ct, "other".toByteArray())
            fail("空明文的 AAD 不匹配也必须失败")
        } catch (expected: Exception) {
            // 预期
        }
    }

    @Test
    fun `同一明文两次加密产生不同密文（随机 IV）`() {
        val plaintext = "same".toByteArray()
        val a = CryptoPrimitives.aesGcmEncrypt(key, plaintext)
        val b = CryptoPrimitives.aesGcmEncrypt(key, plaintext)
        assertFalse("随机 IV 必须让密文不同，否则会泄露明文是否重复", a.contentEquals(b))
        assertArrayEquals(CryptoPrimitives.aesGcmDecrypt(key, a), CryptoPrimitives.aesGcmDecrypt(key, b))
    }

    @Test
    fun `密文被篡改时解密必须失败`() {
        val ct = CryptoPrimitives.aesGcmEncrypt(key, "secret".toByteArray())
        // 翻转最后一个字节（落在认证标签内）
        val tampered = ct.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()
        try {
            CryptoPrimitives.aesGcmDecrypt(key, tampered)
            fail("篡改后的密文绝不能被成功解密")
        } catch (expected: Exception) {
            assertTrue(expected is javax.crypto.AEADBadTagException || expected is javax.crypto.BadPaddingException)
        }
    }

    @Test
    fun `AAD 不匹配时解密必须失败`() {
        val aadA = "field:password|entry:1".toByteArray()
        val aadB = "field:password|entry:2".toByteArray()
        val ct = CryptoPrimitives.aesGcmEncrypt(key, "p@ss".toByteArray(), aadA)
        try {
            CryptoPrimitives.aesGcmDecrypt(key, ct, aadB)
            fail("AAD 把密文绑定到具体条目，换条目必须解密失败")
        } catch (expected: Exception) {
            // 预期
        }
    }

    @Test
    fun `错误密钥解密失败`() {
        val ct = CryptoPrimitives.aesGcmEncrypt(key, "data".toByteArray())
        val wrong = ByteArray(32) { (it + 1).toByte() }
        try {
            CryptoPrimitives.aesGcmDecrypt(wrong, ct)
            fail("错误密钥必须解密失败")
        } catch (expected: Exception) {
            // 预期
        }
    }

    @Test
    fun `IV 长度符合 GCM 规范且密文长度等于 明文+IV+Tag`() {
        val plaintext = ByteArray(100)
        val ct = CryptoPrimitives.aesGcmEncrypt(key, plaintext)
        assertEquals(
            plaintext.size + CryptoPrimitives.GCM_IV_BYTES + CryptoPrimitives.GCM_TAG_BITS / 8,
            ct.size,
        )
    }

    @Test
    fun `子密钥派生对不同用途产生不同密钥`() {
        val master = CryptoPrimitives.randomBytes(32)
        val a = CryptoPrimitives.deriveSubKey(master, "field")
        val b = CryptoPrimitives.deriveSubKey(master, "mac")
        assertFalse("用途隔离失败会让一处泄露波及全部", a.contentEquals(b))
        assertEquals(32, a.size)
        // 确定性：同样输入必须得到同样子密钥，否则重启后无法解密
        assertArrayEquals(a, CryptoPrimitives.deriveSubKey(master, "field"))
    }

    @Test
    fun `常量时间比较对内容正确判定`() {
        val a = CryptoPrimitives.randomBytes(32)
        assertTrue(CryptoPrimitives.constantTimeEquals(a, a.copyOf()))
        val b = a.copyOf().also { it[0] = (it[0].toInt() xor 0xFF).toByte() }
        assertFalse(CryptoPrimitives.constantTimeEquals(a, b))
        assertFalse(CryptoPrimitives.constantTimeEquals(a, ByteArray(31)))
    }

    @Test
    fun `清零后内存中不再保留密钥`() {
        val secret = ByteArray(32) { 0x7F }
        CryptoPrimitives.destroy(secret)
        assertArrayEquals(ByteArray(32), secret)
        val chars = charArrayOf('p', 'w')
        CryptoPrimitives.destroy(chars)
        assertArrayEquals(CharArray(2), chars)
    }

    @Test
    fun `HMAC 与 SHA256 输出长度正确`() {
        assertEquals(32, CryptoPrimitives.hmacSha256(key, "m".toByteArray()).size)
        assertEquals(32, CryptoPrimitives.sha256("m".toByteArray()).size)
        assertNotEquals(
            CryptoPrimitives.hmacSha256(key, "a".toByteArray()).toList(),
            CryptoPrimitives.hmacSha256(key, "b".toByteArray()).toList(),
        )
    }

    @Test
    fun `随机字节不具备明显重复`() {
        val a = CryptoPrimitives.randomBytes(64)
        val b = CryptoPrimitives.randomBytes(64)
        assertFalse(a.contentEquals(b))
        // 两次独立取样的重合字节数应远低于「全部相同」；这里只做粗粒度健全性检查
        val overlap = a.count { byte -> b.any { it == byte } }
        assertTrue("随机序列不应完全重合，overlap=$overlap", overlap < a.size)
    }
}
