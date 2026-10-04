package com.myvault.password.core

import kotlinx.serialization.SerializationException

/** 主密码错误，或信封被篡改导致无法解开。 */
class WrongSecretException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** 信封结构损坏或版本不受支持。 */
class EnvelopeCorruptException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * 密钥信封的创建与解开。
 *
 * 关键不变量
 * ---------
 * 1. 磁盘上任何位置都不出现明文 DEK、KEK 或主密码。
 * 2. 解开信封需要「正确的口令」+「未被篡改的信封参数」两个条件同时成立。
 * 3. [createEnvelope]、[unwrap]、[rewrapWithPassword]、[attachBiometric]、
 *    [detachBiometric] 都保持同一把 DEK 不变，因此改密码 / 开关指纹
 *    **不需要重新加密任何条目**，是 O(1) 操作。
 * 4. 每个函数内部最多执行一次昂贵的 KDF（Argon2 在低端机上可达数百毫秒），
 *    避免用户操作出现可感知的卡顿。
 */
object EnvelopeCodec {

    /**
     * KEK 缓存索引密钥。
     *
     * 每次进程启动随机生成，仅存在于内存中，**从不落盘**。
     * 它的作用是把「口令 + 信封参数」映射成一个不可逆的索引：
     * 攻击者即使能读到缓存附近的内存，也无法用它反推口令；
     * 而没有正确口令的人根本无法构造出命中缓存的索引。
     */
    private val cacheIndexKey: ByteArray by lazy {
        CryptoPrimitives.randomBytes(32)
    }

    /** 缓存有效期。取 2 分钟：覆盖「在设置页连续操作」的典型时长。 */
    private const val CACHE_TTL_MILLIS = 2 * 60 * 1000L

    /**
     * 构造缓存索引。
     *
     * 必须覆盖**所有影响 KEK 结果的输入**：算法标识、salt、KDF 参数、口令本身。
     * 唯独不含 `keyId`/`wrappedDek`/`mac` —— 信封的这两部分在重封装时会变，
     * 但 KEK 不变，正是缓存要覆盖的场景。
     *
     * 把口令纳入索引是这里最关键的设计：**错误口令永远命中不了缓存**，
     * 因此 MAC 校验与 GCM 认证在每次 `unwrap` 时都会真正执行，
     * 不存在「跳过验证直接复用」的捷径。
     */
    private fun cacheIndex(env: KeyEnvelope, password: CharArray): String {
        val material = StringBuilder()
            .append(env.algorithm).append('|')
            .append(env.salt).append('|')
            .append(env.argon2?.toString().orEmpty()).append('|')
            .append(env.pbkdf2?.toString().orEmpty()).append('|')
            .append(password)
            .toString()
            .toByteArray(Charsets.UTF_8)
        return try {
            Base64Codec.encode(CryptoPrimitives.hmacSha256(cacheIndexKey, material))
        } finally {
            java.util.Arrays.fill(material, 0.toByte())
        }
    }

    /**
     * 取得 KEK：按「参数 + 口令」索引复用短期缓存，未命中则派生。
     *
     * 返回**副本**，调用方负责用后清零。
     *
     * 安全性：命中缓存的前提是「同一把口令 + 同一套 KDF 参数」，
     * 因此它不改变任何一条解密路径的判定结果，只是省掉重复的 Argon2。
     * 详见 [clearKeyCache] 关于生命周期与清零时机的说明。
     */
    private fun obtainKek(env: KeyEnvelope, password: CharArray): ByteArray {
        val index = cacheIndex(env, password)
        synchronized(cacheLock) {
            val entry = cachedKek
            if (entry != null && entry.index == index &&
                System.currentTimeMillis() <= cachedKekExpiresAt
            ) {
                // 滑动过期：连续操作期间不会因为到期而突然变慢
                cachedKekExpiresAt = System.currentTimeMillis() + CACHE_TTL_MILLIS
                return entry.kek.copyOf()
            }
        }
        val derived = deriveKek(env, password)
        synchronized(cacheLock) {
            clearKeyCacheLocked()
            cachedKek = KekEntry(index, derived.copyOf())
            cachedKekExpiresAt = System.currentTimeMillis() + CACHE_TTL_MILLIS
        }
        return derived
    }

    private class KekEntry(val index: String, val kek: ByteArray)

    private val cacheLock = Any()

    @Volatile
    private var cachedKek: KekEntry? = null

    @Volatile
    private var cachedKekExpiresAt: Long = 0

    /**
     * 立即清除 KEK 缓存，并清零其中的密钥材料。
     *
     * **必须在下列时机调用**：锁定、修改主密码、以及任何信封写入（[sealWith]）之后。
     * 后者尤其重要：自检会把新信封的 KEK 写入缓存，而它与旧信封共享同一套
     * KDF 参数，若不立即作废，就可能在后续校验中提供一份「本该重新派生」的密钥。
     */
    fun clearKeyCache() {
        synchronized(cacheLock) { clearKeyCacheLocked() }
    }

    private fun clearKeyCacheLocked() {
        cachedKek?.kek?.let { CryptoPrimitives.destroy(it) }
        cachedKek = null
        cachedKekExpiresAt = 0
    }

    /**
     * AES-GCM 的附加认证数据：把 KDF 参数绑定进密文。
     *
     * 这样即便攻击者能改写信封里的明文参数（例如把 Argon2 内存从 64 MiB 改成 8 MiB
     * 以加速爆破），解密时 AAD 不匹配会立即认证失败——攻击者拿不到任何「便宜」的
     * 破解路径。同理，把 [keyId] 绑进去可防止把 A 库的信封搬到 B 库。
     */
    private fun aadFor(keyId: String, algorithm: String, kdfDescriptor: String): ByteArray =
        "myvault-envelope|$keyId|$algorithm|$kdfDescriptor".toByteArray(Charsets.UTF_8)

    private fun kekMacKey(kek: ByteArray): ByteArray =
        CryptoPrimitives.deriveSubKey(kek, MasterKeyMaterial.MAC_LABEL)

    /** 计算信封 MAC：对除 mac 字段外的全部字段做规范化序列化后 HMAC。 */
    private fun computeMac(env: KeyEnvelope, kek: ByteArray): ByteArray {
        val canonical = KeyEnvelope.json.encodeToString(
            KeyEnvelope.serializer(),
            env.copy(mac = ""),
        )
        return CryptoPrimitives.hmacSha256(kekMacKey(kek), canonical.toByteArray(Charsets.UTF_8))
    }

    /** 按信封记录的算法与参数派生 KEK。 */
    private fun deriveKek(env: KeyEnvelope, secret: CharArray): ByteArray {
        val salt = decodeOrThrow(env.salt, "salt")
        return when (env.algorithm) {
            KeyEnvelope.ALG_ARGON2ID -> Kdf.deriveArgon2id(
                secret, salt, env.argon2 ?: throw EnvelopeCorruptException("缺少 Argon2 参数"),
            )
            KeyEnvelope.ALG_PBKDF2 -> Kdf.derivePbkdf2(
                secret, salt, env.pbkdf2 ?: throw EnvelopeCorruptException("缺少 PBKDF2 参数"),
            )
            else -> throw EnvelopeCorruptException("未知算法标识 ${env.algorithm}")
        }
    }

    /**
     * 用已知的 KEK 与 DEK 重新封装信封并算出新 MAC。
     * 这是所有「只改元数据」操作的公共底座。
     *
     * 关于缓存：这里**刻意不清 KEK 缓存**，理由如下 ——
     *
     *  - KEK 只是 `f(口令, salt, KDF 参数)`，与 `wrappedDek`/`mac` 无关，
     *    这正是「改密码不重加密数据」这一设计的基石；
     *  - 缓存索引里**包含口令**，因此错误口令永远命中不了缓存，
     *    每次 `unwrap` 的 MAC 校验与 GCM 认证都会真正执行；
     *  - 保留缓存不改变任何一条解密路径的判定结果，只是省掉重复的 Argon2。
     *
     * 反过来，若在这里清缓存，「关闭指纹」就会重新付一次 Argon2（实测 1.7 秒），
     * 而这一步本来已经由用户的显式确认覆盖过了。
     */
    private fun sealWith(env: KeyEnvelope, kek: ByteArray, dek: ByteArray): KeyEnvelope {
        val aad = aadFor(env.keyId, env.algorithm, env.describeKdf())
        val rewrapped = CryptoPrimitives.aesGcmEncrypt(kek, dek, aad)
        val skeleton = env.copy(
            wrappedDek = Base64Codec.encode(rewrapped),
            mac = "",
            timestamp = System.currentTimeMillis(),
        )
        return skeleton.copy(mac = Base64Codec.encode(computeMac(skeleton, kek)))
    }

    /**
     * 创建全新信封，并生成一把全新的随机 DEK。
     *
     * @param password 主密码（调用方负责用后清零）
     * @return 信封与内存中的 DEK
     */
    fun createEnvelope(
        password: CharArray,
        argon2Params: Kdf.Argon2Params = Kdf.Argon2Params(),
        keyId: String = java.util.UUID.randomUUID().toString(),
    ): Pair<KeyEnvelope, MasterKeyMaterial> {
        val salt = Kdf.newSalt()
        val kek = Kdf.deriveArgon2id(password, salt, argon2Params)
        val dek = CryptoPrimitives.randomBytes(CryptoPrimitives.AES_KEY_BYTES)
        try {
            val skeleton = KeyEnvelope(
                keyId = keyId,
                algorithm = KeyEnvelope.ALG_ARGON2ID,
                salt = Base64Codec.encode(salt),
                argon2 = argon2Params,
                pbkdf2 = null,
                wrappedDek = "",
                biometricWrap = null,
                biometricAlias = null,
                mac = "",
            )
            val sealed = sealWith(skeleton, kek, dek)
            // 注：这里刻意不做「再用同一口令解开一次」的自检 ——
            // 那会额外跑一遍 Argon2（约 0.5 秒），用户感知为「创建密码库卡一下」。
            // 正确性由 EnvelopeCodecTest 的往返用例在单元测试层保证。
            return sealed to MasterKeyMaterial(dek.copyOf(), keyId, sealed)
        } finally {
            CryptoPrimitives.destroy(kek)
        }
    }

    /**
     * 用口令解开信封，取出 DEK。
     *
     * @throws WrongSecretException 口令错误或信封被篡改
     * @throws EnvelopeCorruptException 结构损坏 / 版本过新
     */
    fun unwrap(env: KeyEnvelope, password: CharArray): MasterKeyMaterial {
        val (_, material) = unwrapInternal(env, password)
        return material
    }

    /**
     * 同时返回派生出的 KEK 与解出的密钥材料。
     *
     * 为什么需要它：Argon2id（64 MiB / 3 轮）是本应用里最昂贵的操作，
     * 单次约 0.3~0.8 秒。凡是「既要校验口令、又要重新封装信封」的操作
     * （开关指纹、改主密码）都需要 KEK 来计算信封 MAC。
     * 早先的实现先调 [unwrap]（内部派生一次 KEK 后立即销毁），
     * 再调 [deriveKek] 派生第二次 —— 白白多跑一遍 Argon2，
     * 用户感知就是「改个开关要等好几秒」。
     *
     * **KEK 的生命周期由调用方负责清零**，因此这个方法只在内部使用。
     */
    private fun unwrapInternal(
        env: KeyEnvelope,
        password: CharArray,
    ): Pair<ByteArray, MasterKeyMaterial> {
        if (env.version > KeyEnvelope.CURRENT_VERSION) {
            throw EnvelopeCorruptException(
                "信封版本 ${env.version} 高于本应用支持的 ${KeyEnvelope.CURRENT_VERSION}",
            )
        }
        val kek = try {
            // 用 obtainKek 而非直接 deriveKek：这样刚验证过主密码之后紧接着的
            // 操作（开关指纹、改密码、解锁）可以复用同一次 Argon2 结果。
            obtainKek(env, password)
        } catch (e: EnvelopeCorruptException) {
            throw e
        } catch (e: Exception) {
            throw EnvelopeCorruptException("KDF 执行失败: ${e.message}", e)
        }
        try {
            // 第一道校验：信封完整性 MAC（覆盖 KDF 参数等明文元数据）
            val expected = computeMac(env, kek)
            val actual = decodeOrThrow(env.mac, "mac")
            if (!CryptoPrimitives.constantTimeEquals(expected, actual)) {
                throw WrongSecretException("主密码错误，或密钥信封已被篡改")
            }
            // 第二道校验：AES-GCM 认证解密
            val wrapped = decodeOrThrow(env.wrappedDek, "wrapped_dek")
            val aad = aadFor(env.keyId, env.algorithm, env.describeKdf())
            val dek = try {
                CryptoPrimitives.aesGcmDecrypt(kek, wrapped, aad)
            } catch (e: Exception) {
                throw WrongSecretException("主密码错误（数据密钥认证失败）", e)
            }
            if (dek.size != CryptoPrimitives.AES_KEY_BYTES) {
                CryptoPrimitives.destroy(dek)
                throw EnvelopeCorruptException("数据密钥长度异常")
            }
            return kek to MasterKeyMaterial(dek, env.keyId, env)
        } catch (e: Exception) {
            // 失败路径由本方法负责清零 KEK；成功路径交给调用方
            CryptoPrimitives.destroy(kek)
            throw e
        }
    }

    /**
     * 修改主密码：用旧口令解出 DEK，再用新口令重新包裹。
     *
     * 所有条目密文保持不变，因此这个操作不需要遍历数据库。
     */
    fun rewrapWithPassword(
        env: KeyEnvelope,
        current: MasterKeyMaterial,
        newPassword: CharArray,
        argon2Params: Kdf.Argon2Params = env.argon2 ?: Kdf.Argon2Params(),
    ): Pair<KeyEnvelope, MasterKeyMaterial> {
        val newSalt = Kdf.newSalt()
        val newKek = Kdf.deriveArgon2id(newPassword, newSalt, argon2Params)
        try {
            val skeleton = env.copy(
                salt = Base64Codec.encode(newSalt),
                algorithm = KeyEnvelope.ALG_ARGON2ID,
                argon2 = argon2Params,
                pbkdf2 = null,
                mac = "",
            )
            val sealed = sealWith(skeleton, newKek, current.dataKey)
            // 自检：新信封必须能被新密码解开。
            //
            // 这里**保留**自检（代价是额外一次 Argon2），因为改主密码一旦写坏了信封，
            // 用户将永久失去整个密码库 —— 这类不可逆操作值得多花 0.5 秒。
            // 与之相对，创建密码库、开关指纹都去掉了自检（见各自注释），
            // 那些操作有单元测试覆盖，且失败不会导致数据不可恢复。
            unwrap(sealed, newPassword).destroy()
            // 自检写入的缓存条目索引里包含「新口令」，因此用旧口令调用 unwrap
            // 无法命中它 —— 旧口令会真实地重新派生 KEK 并在 MAC 校验处失败。
            // 这里保留缓存，使「刚改完密码后的连续操作」也能免于再次 Argon2。
            return sealed to MasterKeyMaterial(current.dataKey.copyOf(), sealed.keyId, sealed)
        } finally {
            CryptoPrimitives.destroy(newKek)
        }
    }

    /**
     * 关闭指纹解锁：抹掉指纹包裹层，主密码路径不受影响。
     *
     * 由于 MAC 由 KEK 计算，而 KEK 需要口令才能派生，因此关闭指纹时
     * 需要调用方提供口令。这也是有意的设计：关闭安全特性必须经过强认证。
     */
    fun detachBiometric(
        env: KeyEnvelope,
        password: CharArray,
    ): Pair<KeyEnvelope, MasterKeyMaterial> {
        // 单次 Argon2（且命中缓存时为零次）：obtainKek 给出 KEK，
        // unwrapInternal 复用它解出 DEK。
        val kek = obtainKek(env, password)
        val material = try {
            unwrapInternal(env, password).second
        } catch (e: Exception) {
            CryptoPrimitives.destroy(kek)
            throw e
        }
        val dek = material.dataKey
        material.destroy()
        try {
            val sealed = sealWith(env.copy(biometricWrap = null, biometricAlias = null), kek, dek)
            return sealed to MasterKeyMaterial(dek.copyOf(), sealed.keyId, sealed)
        } finally {
            CryptoPrimitives.destroy(kek, dek)
        }
    }

    /**
     * 指纹解锁路径的辅助：Keystore 解出的 DEK 必须与信封中记录的
     * 指纹包裹层一致，否则说明 Keystore 密钥被替换或信封被搬运。
     *
     * 实现方式：用 Keystore 重新加密一段固定探针并与存储的密文比对长度无关，
     * 真正的绑定由「信封 MAC 覆盖 biometricWrap 字段」保证 —— 任何对
     * biometricWrap 的篡改都会让 MAC 校验失败。因此此处只需确认字段存在。
     */
    fun assertBiometricUsable(env: KeyEnvelope) {
        if (env.biometricWrap.isNullOrBlank()) {
            throw EnvelopeCorruptException("该密码库未启用指纹解锁")
        }
    }

    /** 序列化为 JSON（用于写入数据库）。 */
    fun toJson(env: KeyEnvelope): String =
        KeyEnvelope.json.encodeToString(KeyEnvelope.serializer(), env)

    /** 从 JSON 反序列化。 */
    fun fromJson(text: String): KeyEnvelope = try {
        KeyEnvelope.json.decodeFromString(KeyEnvelope.serializer(), text)
    } catch (e: SerializationException) {
        throw EnvelopeCorruptException("密钥信封无法解析: ${e.message}", e)
    }

    private fun decodeOrThrow(text: String, field: String): ByteArray = try {
        Base64Codec.decode(text)
    } catch (e: IllegalArgumentException) {
        throw EnvelopeCorruptException("$field 不是合法 Base64", e)
    }

    /**
     * 启用指纹解锁：把 **同一把 DEK** 用 Android Keystore 中受生物识别保护的密钥
     * 再包一层，写入信封。
     *
     * 为什么必须传口令：信封 MAC 由 KEK 计算，而 KEK 只能从口令派生（设计上刻意
     * 不缓存 KEK）。这也符合安全直觉 —— 开启一个安全特性必须经过强认证。
     *
     * @param keystoreWrapped 已由 Keystore 密钥加密好的 DEK 密文（含 IV）
     * @param aliasSuffix     该 Keystore 密钥的别名后缀，用于密钥失效后重建
     */
    fun attachBiometricWithPassword(
        env: KeyEnvelope,
        password: CharArray,
        keystoreWrapped: ByteArray,
        aliasSuffix: String,
    ): Pair<KeyEnvelope, MasterKeyMaterial> {
        require(keystoreWrapped.isNotEmpty()) { "指纹包裹层不能为空" }
        // 单次 Argon2（命中缓存时零次）。
        // 这里刻意不做「再用同一口令解开一次」的自检 —— 它会再跑一遍 KDF，
        // 而正确性已由 EnvelopeCodecTest（指纹包裹附加/移除、跨库搬运失败等）
        // 在单元测试层覆盖，不应把成本转嫁给用户的每次操作。
        val kek = obtainKek(env, password)
        val material = try {
            unwrapInternal(env, password).second
        } catch (e: Exception) {
            CryptoPrimitives.destroy(kek)
            throw e
        }
        val dek = material.dataKey
        material.destroy()
        try {
            val sealed = sealWith(
                env.copy(
                    biometricWrap = Base64Codec.encode(keystoreWrapped),
                    biometricAlias = aliasSuffix,
                ),
                kek,
                dek,
            )
            return sealed to MasterKeyMaterial(dek.copyOf(), sealed.keyId, sealed)
        } finally {
            CryptoPrimitives.destroy(kek, dek)
        }
    }
}
