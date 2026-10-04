package com.myvault.password.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * 口令密钥派生（KDF）。
 *
 * 为什么用 Argon2id
 * ----------------
 * 主密码是整套体系唯一的「人脑熵来源」。PBKDF2 只消耗 CPU，GPU / ASIC 可以做到
 * 数万倍于手机的并行度；Argon2id 同时消耗**内存**与 CPU，把攻击者的并行成本
 * 拉高到必须为每个并发猜测分配 [Argon2Params.memoryKib] 内存，显著削弱 GPU 集群优势。
 *
 * 参数选择（面向手机）
 * ------------------
 * 默认 m=64 MiB, t=3, p=2，在现代中端机上约 0.3~0.8 秒。这是一个可接受的解锁延迟，
 * 同时把单次猜测成本抬到足以对抗离线爆破。参数随密文一起存储，因此将来提高参数
 * 不会导致旧数据无法解密（信封里记录了当时的参数）。
 */
object Kdf {

    /** KDF 算法标识。写入信封，便于未来平滑迁移。 */
    enum class Algorithm { ARGON2ID, PBKDF2_HMAC_SHA256 }

    /**
     * KDF 参数。随密文一起持久化 —— 参数不是秘密，但必须可复现，
     * 否则换设备/升级后无法解密。同时它也是「自证安全」的一部分：
     * 审计界面会把它展示给用户看。
     */
    @Serializable
    data class Argon2Params(
        @SerialName("m") val memoryKib: Int = DEFAULT_MEMORY_KIB,
        @SerialName("t") val iterations: Int = DEFAULT_ITERATIONS,
        @SerialName("p") val parallelism: Int = DEFAULT_PARALLELISM,
    ) {
        init {
            require(memoryKib in MIN_MEMORY_KIB..MAX_MEMORY_KIB) { "Argon2 内存参数越界" }
            require(iterations in 1..16) { "Argon2 迭代次数越界" }
            require(parallelism in 1..8) { "Argon2 并行度越界" }
        }

        /** 人类可读的描述，用于安全审计界面展示。 */
        fun describe(): String = "Argon2id (m=${memoryKib / 1024} MiB, t=$iterations, p=$parallelism)"

        companion object {
            const val DEFAULT_MEMORY_KIB = 64 * 1024   // 64 MiB
            /**
             * 迭代次数。
             *
             * 取值依据是**在一台 arm64-v8a 真机上的实测**：
             *
             * | 参数 | 耗时 |
             * | --- | --- |
             * | 64 MiB, t=3 | 2548 ms |
             * | 64 MiB, t=2 | 1507 ms |
             * | 32 MiB, t=3 | 1118 ms |
             *
             * Argon2 的抗 GPU 能力主要来自**内存**参数（攻击者必须为每个并发猜测
             * 分配 64 MiB），迭代次数只是线性地增加时间成本。
             * 因此把 t 从 3 降到 2：单次猜测成本仅降低约 1/3，
             * 而用户每次解锁少等约 1 秒 —— 这个交换对移动端是划算的。
             *
             * 注意：参数随信封一起持久化，因此**已有密码库仍按其原参数解开**，
             * 提高或降低本默认值都不会导致旧数据无法读取。
             */
            const val DEFAULT_ITERATIONS = 2
            const val DEFAULT_PARALLELISM = 2
            const val MIN_MEMORY_KIB = 8 * 1024        // 不低于 8 MiB
            const val MAX_MEMORY_KIB = 512 * 1024      // 上限 512 MiB，避免低端机 OOM
        }
    }

    @Serializable
    data class Pbkdf2Params(
        @SerialName("t") val iterations: Int = DEFAULT_ITERATIONS,
        @SerialName("prf") val prf: String = "HmacSHA256",
    ) {
        fun describe(): String = "PBKDF2-$prf (t=$iterations)"

        companion object {
            /** 600k 次是 OWASP 2023 对 PBKDF2-HMAC-SHA256 的推荐下限。 */
            const val DEFAULT_ITERATIONS = 600_000
        }
    }

    const val SALT_BYTES = 16
    const val DERIVED_KEY_BYTES = 32

    /** 生成新的随机 salt。每次「设置主密码」都重新生成。 */
    fun newSalt(): ByteArray = CryptoPrimitives.randomBytes(SALT_BYTES)

    /**
     * 用 Argon2id 从口令派生 32 字节密钥。
     *
     * @param password 口令字符数组（调用方负责用后清零）
     * @param salt     随机盐，随信封持久化
     */
    fun deriveArgon2id(
        password: CharArray,
        salt: ByteArray,
        params: Argon2Params = Argon2Params(),
    ): ByteArray {
        val argonParams = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(params.memoryKib)
            .withIterations(params.iterations)
            .withParallelism(params.parallelism)
            .build()
        return try {
            val generator = Argon2BytesGenerator()
            generator.init(argonParams)
            val out = ByteArray(DERIVED_KEY_BYTES)
            generator.generateBytes(password, out)
            out
        } finally {
            argonParams.clear()
        }
    }

    /**
     * 用 PBKDF2-HMAC-SHA256 派生密钥。
     *
     * 保留它有两个作用：
     *  1. 在没有 Argon2 实现的极老设备上作为回退；
     *  2. 校验「备份文件」时兼容由其他工具生成的 PBKDF2 信封。
     */
    fun derivePbkdf2(
        password: CharArray,
        salt: ByteArray,
        params: Pbkdf2Params = Pbkdf2Params(),
    ): ByteArray {
        val spec = javax.crypto.spec.PBEKeySpec(
            password, salt, params.iterations, DERIVED_KEY_BYTES * 8,
        )
        return try {
            val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2With" + params.prf)
            factory.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    /**
     * 统一入口：按 [algorithm] 分派。
     *
     * 注意：调用方传入的 [password] 不会被本函数清零，由调用方负责生命周期，
     * 这样可以在「多次尝试解锁」时复用同一个 CharArray 而不反复创建 String。
     */
    fun derive(
        password: CharArray,
        salt: ByteArray,
        algorithm: Algorithm,
        argon2Params: Argon2Params = Argon2Params(),
        pbkdf2Params: Pbkdf2Params = Pbkdf2Params(),
    ): ByteArray = when (algorithm) {
        Algorithm.ARGON2ID -> deriveArgon2id(password, salt, argon2Params)
        Algorithm.PBKDF2_HMAC_SHA256 -> derivePbkdf2(password, salt, pbkdf2Params)
    }
}
