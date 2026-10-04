package com.myvault.password.core

/**
 * 密码学原语：对称加密与完整性校验。
 *
 * 设计要点
 * --------
 * 1. 全程只使用 JDK / Android 平台自带的 JCE 实现（AES-GCM、HMAC-SHA256、SHA-256、
 *    PBKDF2），外加 BouncyCastle 提供的 Argon2id。**不引入任何自定义密码算法**。
 * 2. 所有加密均使用 AES-256-GCM，认证标签 128 bit。GCM 同时提供机密性与完整性，
 *    因此密文被篡改时解密必然失败（认证失败抛异常），不会返回错误明文。
 * 3. 每个字段独立随机 nonce（Android 的 SecureRandom，由内核 CSPRNG 播种），
 *    在 2^96 的 nonce 空间中，单个设备终身碰撞概率可忽略；同时对库整体再叠加
 *    一层 HMAC-SHA256（以独立子密钥加密），用于检测「密文整体被替换/重排」这类
 *    单字段 GCM 无法覆盖的攻击。
 * 4. 所有中间密钥材料在使用后立即清零（[destroy]），不等待 GC。
 *
 * 本文件只依赖标准 JCE，因此可以在 JVM 单元测试中直接运行（无需 Android 运行时）。
 */
object CryptoPrimitives {

    const val AES_KEY_BYTES = 32      // AES-256
    const val GCM_IV_BYTES = 12       // GCM 推荐 96 bit nonce
    const val GCM_TAG_BITS = 128      // 认证标签长度
    const val HMAC_KEY_BYTES = 32     // HMAC-SHA256 子密钥
    const val HMAC_BYTES = 32

    private const val AES_TRANSFORM = "AES/GCM/NoPadding"
    private const val HMAC_ALGORITHM = "HmacSHA256"

    /** 生成 [size] 字节的密码学安全随机数。 */
    fun randomBytes(size: Int): ByteArray {
        require(size > 0) { "randomBytes size 必须为正数" }
        val out = ByteArray(size)
        SecureRandomHolder.INSTANCE.nextBytes(out)
        return out
    }

    /**
     * 使用 [key] 对 [plaintext] 做 AES-256-GCM 加密。
     *
     * @param aad 附加认证数据（不加密但参与认证）。用于把「这条密文属于哪个字段/
     *            哪个条目」绑定进去，防止把 A 条目的密文搬到 B 条目。
     * @return [IV(12) || 密文 || 认证标签(16)]
     */
    fun aesGcmEncrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        require(key.size == AES_KEY_BYTES) { "AES-256 需要 32 字节密钥，实际 ${key.size}" }
        val iv = randomBytes(GCM_IV_BYTES)
        val cipher = javax.crypto.Cipher.getInstance(AES_TRANSFORM)
        cipher.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(GCM_TAG_BITS, iv),
        )
        if (aad != null) cipher.updateAAD(aad)
        val body = cipher.doFinal(plaintext)
        // IV 前置，便于解密时读取
        return iv + body
    }

    /** 密文的最小合法长度：IV 与认证标签都在，明文可以为空。 */
    const val MIN_CIPHERTEXT_BYTES = GCM_IV_BYTES + GCM_TAG_BITS / 8

    /**
     * 解密 [aesGcmEncrypt] 的输出。密文或 AAD 不匹配时抛出
     * [javax.crypto.AEADBadTagException]，绝不返回错误明文。
     *
     * 长度校验必须用 `>=` 而不是 `>`：**空明文是合法的**，
     * 它恰好产生 `IV(12) + Tag(16) = 28` 字节的密文。
     *
     * 这里曾经写成 `> 28`，导致所有「留空字段」在读取时抛
     * 「密文长度不合法」。后果非常隐蔽：写入完全成功，只有在读回时才失败，
     * 而上层为了容错会静默跳过这条记录 —— 表现为
     * **「新建条目保存不了、也不报错」**。这是一个真实的线上缺陷。
     */
    fun aesGcmDecrypt(key: ByteArray, ciphertext: ByteArray, aad: ByteArray? = null): ByteArray {
        require(key.size == AES_KEY_BYTES) { "AES-256 需要 32 字节密钥，实际 ${key.size}" }
        require(ciphertext.size >= MIN_CIPHERTEXT_BYTES) {
            "密文长度不合法：至少需要 $MIN_CIPHERTEXT_BYTES 字节（IV + Tag），实际 ${ciphertext.size}"
        }
        val iv = ciphertext.copyOfRange(0, GCM_IV_BYTES)
        val body = ciphertext.copyOfRange(GCM_IV_BYTES, ciphertext.size)
        val cipher = javax.crypto.Cipher.getInstance(AES_TRANSFORM)
        cipher.init(
            javax.crypto.Cipher.DECRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(GCM_TAG_BITS, iv),
        )
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(body)
    }

    /** 计算 HMAC-SHA256。用于完整性校验与 KDF 子密钥派生。 */
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance(HMAC_ALGORITHM)
        mac.init(javax.crypto.spec.SecretKeySpec(key, HMAC_ALGORITHM))
        return mac.doFinal(data)
    }

    fun sha256(data: ByteArray): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return md.digest(data)
    }

    /** 常量时间比较，避免通过响应时间侧信道推断 MAC。 */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean =
        java.security.MessageDigest.isEqual(a, b)

    /**
     * 从主密钥派生用途隔离的子密钥（HKDF 的简化形式）。
     *
     * 直接复用主密钥做多种用途（加密字段、算 MAC、加密备份）是危险的：
     * 一旦某处泄露会波及全部。这里用 HMAC-SHA256(masterKey, label) 为每个用途
     * 派生互不相关的独立子密钥。
     */
    fun deriveSubKey(masterKey: ByteArray, label: String): ByteArray =
        hmacSha256(masterKey, label.toByteArray(Charsets.UTF_8))

    /** 立即清零字节数组，降低密钥在内存中残留的窗口。 */
    fun destroy(vararg secrets: ByteArray?) {
        for (s in secrets) {
            if (s != null) java.util.Arrays.fill(s, 0.toByte())
        }
    }

    /** 把 CharArray 中的口令清零（String 无法清零，故内部统一使用 CharArray 传递）。 */
    fun destroy(vararg secrets: CharArray?) {
        for (s in secrets) {
            if (s != null) java.util.Arrays.fill(s, '\u0000')
        }
    }

    /**
     * SecureRandom 单例。Android 上由 OpenSSL/BoringSSL CSPRNG 提供，
     * 具备内核熵池播种，无需手动 setSeed。
     */
    private object SecureRandomHolder {
        val INSTANCE: java.security.SecureRandom = java.security.SecureRandom()
    }
}
