package com.myvault.password.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * 密钥信封测试。
 *
 * Argon2 参数被刻意调小（8 MiB / 1 轮），让测试在 JVM 上秒级完成。
 * 参数变小**不影响**被测逻辑的正确性：解封路径完全按信封里记录的参数执行。
 */
class EnvelopeCodecTest {

    private val fastArgon2 = Kdf.Argon2Params(memoryKib = 8 * 1024, iterations = 1, parallelism = 1)

    private fun pwd(s: String) = s.toCharArray()

    @Test
    fun `创建信封后可被同一口令解开且取出同一把数据密钥`() {
        val password = pwd("correct horse battery staple")
        val (env, material) = EnvelopeCodec.createEnvelope(password, fastArgon2)
        try {
            val reopened = EnvelopeCodec.unwrap(env, password)
            try {
                assertArrayEquals(material.dataKey, reopened.dataKey)
                assertEquals(env.keyId, reopened.keyId)
            } finally {
                reopened.destroy()
            }
        } finally {
            material.destroy()
        }
    }

    @Test
    fun `错误口令必须被拒绝`() {
        val (env, material) = EnvelopeCodec.createEnvelope(pwd("right-password-123"), fastArgon2)
        material.destroy()
        try {
            EnvelopeCodec.unwrap(env, pwd("wrong-password-123"))
            fail("错误口令绝不能被接受")
        } catch (expected: WrongSecretException) {
            assertNotNull(expected.message)
        }
    }

    @Test
    fun `信封中不出现明文口令或数据密钥`() {
        val password = "SuperSecret-Master-Password-2026"
        val (env, material) = EnvelopeCodec.createEnvelope(pwd(password), fastArgon2)
        try {
            val json = EnvelopeCodec.toJson(env)
            assertFalse("序列化结果不能包含主密码", json.contains(password))
            val dekBase64 = Base64Codec.encode(material.dataKey)
            assertFalse("序列化结果不能包含明文数据密钥", json.contains(dekBase64))
            assertFalse(
                "也不应包含数据密钥的十六进制形式",
                json.contains(material.dataKey.joinToString("") { "%02x".format(it) }),
            )
        } finally {
            material.destroy()
        }
    }

    @Test
    fun `篡改 KDF 参数会被完整性 MAC 发现`() {
        val password = pwd("password-for-downgrade-test")
        val (env, material) = EnvelopeCodec.createEnvelope(password, fastArgon2)
        material.destroy()
        // 攻击者试图改动信封里的明文元数据：
        // (a) 改高迭代次数会让攻击者更吃力，所以真正的攻击方向是「改低」或「换 salt」。
        //     由于 Argon2Params 自身对上下界有校验，这里用一个仍然合法但不同的
        //     参数值来验证 MAC 的覆盖范围；(b) 换掉 salt。
        val differentIterations = env.copy(argon2 = env.argon2!!.copy(iterations = env.argon2.iterations + 1))
        assertEquals(
            "测试前提：确实构造出了不同的信封",
            false, differentIterations == env,
        )
        try {
            EnvelopeCodec.unwrap(differentIterations, password)
            fail("KDF 参数被改动后 MAC 必须失配")
        } catch (expected: WrongSecretException) {
            // 预期
        }

        val rawSalt = Base64Codec.decode(env.salt)
        rawSalt[0] = (rawSalt[0].toInt() xor 0x01).toByte()
        val swappedSalt = env.copy(salt = Base64Codec.encode(rawSalt))
        try {
            EnvelopeCodec.unwrap(swappedSalt, password)
            fail("salt 被改动后必须无法解开")
        } catch (expected: Exception) {
            assertTrue(expected is WrongSecretException || expected is EnvelopeCorruptException)
        }
    }

    @Test
    fun `篡改密文会被完整性校验发现`() {
        val password = pwd("password-for-tamper-test")
        val (env, material) = EnvelopeCodec.createEnvelope(password, fastArgon2)
        material.destroy()
        val raw = Base64Codec.decode(env.wrappedDek)
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0x01).toByte()
        val tampered = env.copy(wrappedDek = Base64Codec.encode(raw))
        try {
            EnvelopeCodec.unwrap(tampered, password)
            fail("密文被改动后必须解密失败")
        } catch (expected: Exception) {
            assertTrue(expected is WrongSecretException || expected is EnvelopeCorruptException)
        }
    }

    @Test
    fun `改主密码后数据密钥不变且新旧口令行为符合预期`() {
        val oldPwd = pwd("old-password-000")
        val newPwd = pwd("new-password-111")
        val (env, material) = EnvelopeCodec.createEnvelope(oldPwd, fastArgon2)
        val originalDek = material.dataKey.copyOf()
        try {
            val (reEnv, reMaterial) = EnvelopeCodec.rewrapWithPassword(env, material, newPwd, fastArgon2)
            try {
                assertArrayEquals(
                    "改密码不应更换数据密钥，否则要重新加密全部条目",
                    originalDek, reMaterial.dataKey,
                )
                // 新口令可用
                EnvelopeCodec.unwrap(reEnv, newPwd).destroy()
                // 旧口令失效
                try {
                    EnvelopeCodec.unwrap(reEnv, oldPwd)
                    fail("旧口令在改密码后必须失效")
                } catch (expected: WrongSecretException) {
                    // 预期
                }
            } finally {
                reMaterial.destroy()
            }
        } finally {
            CryptoPrimitives.destroy(originalDek)
            material.destroy()
        }
    }

    @Test
    fun `指纹包裹层可附加与移除且不影响主密码路径`() {
        val password = pwd("password-with-biometric")
        val (env, material) = EnvelopeCodec.createEnvelope(password, fastArgon2)
        material.destroy()
        // 用一段任意字节模拟「被 Keystore 包裹后的 DEK」
        val fakeKeystoreWrapped = CryptoPrimitives.randomBytes(64)
        val (withBio, bioMaterial) = EnvelopeCodec.attachBiometricWithPassword(
            env, password, fakeKeystoreWrapped, "suffix-1",
        )
        bioMaterial.destroy()
        assertNotNull(withBio.biometricWrap)
        assertEquals("suffix-1", withBio.biometricAlias)
        // 主密码仍可解
        EnvelopeCodec.unwrap(withBio, password).destroy()

        val (withoutBio, plainMaterial) = EnvelopeCodec.detachBiometric(withBio, password)
        plainMaterial.destroy()
        assertNull(withoutBio.biometricWrap)
        assertNull(withoutBio.biometricAlias)
        EnvelopeCodec.unwrap(withoutBio, password).destroy()
    }

    @Test
    fun `序列化往返保持等价`() {
        val password = pwd("roundtrip-password")
        val (env, material) = EnvelopeCodec.createEnvelope(password, fastArgon2)
        material.destroy()
        val restored = EnvelopeCodec.fromJson(EnvelopeCodec.toJson(env))
        assertEquals(env, restored)
        EnvelopeCodec.unwrap(restored, password).destroy()
    }

    @Test
    fun `版本过新的信封被明确拒绝而不是静默误读`() {
        val password = pwd("version-test-password")
        val (env, material) = EnvelopeCodec.createEnvelope(password, fastArgon2)
        material.destroy()
        val future = env.copy(version = KeyEnvelope.CURRENT_VERSION + 1)
        try {
            EnvelopeCodec.unwrap(future, password)
            fail("不能假装能读懂未来版本的信封")
        } catch (expected: EnvelopeCorruptException) {
            assertTrue(expected.message!!.contains("版本"))
        }
    }

    @Test
    fun `损坏的 JSON 被报告为信封损坏`() {
        try {
            EnvelopeCodec.fromJson("{ not json at all ")
            fail("损坏的 JSON 应抛 EnvelopeCorruptException")
        } catch (expected: EnvelopeCorruptException) {
            // 预期
        }
    }

    @Test
    fun `不同密码库的信封不能互换`() {
        val password = pwd("same-password-for-both")
        val (envA, matA) = EnvelopeCodec.createEnvelope(password, fastArgon2)
        val (envB, matB) = EnvelopeCodec.createEnvelope(password, fastArgon2)
        try {
            assertNotEquals(envA.keyId, envB.keyId)
            // 把 B 的密文塞进 A 的信封：keyId 绑进 AAD，必须失败
            val frankenstein = envA.copy(wrappedDek = envB.wrappedDek)
            try {
                EnvelopeCodec.unwrap(frankenstein, password)
                fail("跨库搬运密文必须失败")
            } catch (expected: Exception) {
                assertTrue(expected is WrongSecretException || expected is EnvelopeCorruptException)
            }
        } finally {
            matA.destroy()
            matB.destroy()
        }
    }

    @Test
    fun `PBKDF2 回退路径同样可解`() {
        // 直接构造一个 PBKDF2 信封，验证兼容路径
        val password = pwd("pbkdf2-fallback-password")
        val salt = Kdf.newSalt()
        val params = Kdf.Pbkdf2Params(iterations = 10_000)
        val kek = Kdf.derivePbkdf2(password, salt, params)
        val dek = CryptoPrimitives.randomBytes(32)
        val keyId = "legacy-key-id"
        val skeleton = KeyEnvelope(
            keyId = keyId,
            algorithm = KeyEnvelope.ALG_PBKDF2,
            salt = Base64Codec.encode(salt),
            argon2 = null,
            pbkdf2 = params,
            wrappedDek = "",
            mac = "",
        )
        val aad = "myvault-envelope|$keyId|${KeyEnvelope.ALG_PBKDF2}|${skeleton.describeKdf()}".toByteArray()
        val wrapped = CryptoPrimitives.aesGcmEncrypt(kek, dek, aad)
        val withWrapped = skeleton.copy(wrappedDek = Base64Codec.encode(wrapped))
        // 用与 EnvelopeCodec 相同的方式算 MAC
        val macKey = CryptoPrimitives.deriveSubKey(kek, MasterKeyMaterial.MAC_LABEL)
        val canonical = KeyEnvelope.json.encodeToString(KeyEnvelope.serializer(), withWrapped.copy(mac = ""))
        val mac = CryptoPrimitives.hmacSha256(macKey, canonical.toByteArray())
        val env = withWrapped.copy(mac = Base64Codec.encode(mac))

        val material = EnvelopeCodec.unwrap(env, password)
        try {
            assertArrayEquals(dek, material.dataKey)
        } finally {
            material.destroy()
            CryptoPrimitives.destroy(kek, dek)
        }
    }
}
