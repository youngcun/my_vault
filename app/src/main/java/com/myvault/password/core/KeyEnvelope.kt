package com.myvault.password.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * 密钥信封（Key Envelope）。
 *
 * 这是整个密码库的「根」：它把真正用于加密数据的**数据密钥（DEK）** 用
 * **主密码派生出的密钥（KEK）** 包起来存盘。磁盘上永远不会出现明文 DEK，
 * 也不会出现主密码本身或它的哈希。
 *
 * ```
 *   主密码 ──Argon2id(salt, params)──► KEK ──AES-256-GCM──► 包裹后的 DEK
 *   指纹   ──Android Keystore───────► KEK'──AES-256-GCM──► 包裹后的 DEK
 *                                                              │
 *                                                              ▼
 *                                      DEK ──HKDF──► 字段加密子密钥 / MAC 子密钥 / 备份子密钥
 * ```
 *
 * 字段级设计说明
 * ------------
 * - [mac] 是用 KEK 派生的独立子密钥对整个信封其余部分算出的 HMAC-SHA256。
 *   它让「篡改 KDF 参数」这类攻击（例如把迭代次数改成 1 以加速爆破）在解密前
 *   就被发现，而 AES-GCM 的认证标签无法覆盖这些明文参数。
 * - [biometricWrap] 是把**同一个 DEK** 用 Android Keystore 中受生物识别保护的
 *   密钥再包一层。它的存在意味着：指纹解锁与主密码解锁打开的是同一个库，
 *   且修改主密码时无需重新加密任何数据。
 */
@Serializable
data class KeyEnvelope(
    @SerialName("v") val version: Int = CURRENT_VERSION,
    @SerialName("kid") val keyId: String,
    @SerialName("alg") val algorithm: String,
    @SerialName("salt") val salt: String,
    @SerialName("kdf_argon2") val argon2: Kdf.Argon2Params? = null,
    @SerialName("kdf_pbkdf2") val pbkdf2: Kdf.Pbkdf2Params? = null,
    /** 主密码包裹的 DEK（Base64，格式 IV||密文||Tag） */
    @SerialName("wrapped_dek") val wrappedDek: String,
    /** 指纹包裹的 DEK（Base64）；null 表示未启用指纹解锁 */
    @SerialName("bio_dek") val biometricWrap: String? = null,
    /** 指纹解锁所用 Keystore 别名的后缀，便于密钥失效后重新绑定 */
    @SerialName("bio_alias") val biometricAlias: String? = null,
    /** 信封完整性 MAC（Base64），用 KEK 的派生子密钥计算 */
    @SerialName("mac") val mac: String,
    /** 最近一次修改时间（毫秒），仅用于展示与备份比对 */
    @SerialName("ts") val timestamp: Long = System.currentTimeMillis(),
) {

    /** 供安全审计界面展示的算法描述。 */
    fun describeKdf(): String = when {
        argon2 != null -> argon2.describe()
        pbkdf2 != null -> pbkdf2.describe()
        else -> "未知 KDF"
    }

    companion object {
        const val CURRENT_VERSION = 1
        const val ALG_ARGON2ID = "argon2id-aes256gcm"
        const val ALG_PBKDF2 = "pbkdf2-aes256gcm"

        internal val json = Json {
            encodeDefaults = true
            ignoreUnknownKeys = true
            explicitNulls = true
        }
    }
}

/**
 * 已解锁的内存密钥材料。
 *
 * 生命周期与「解锁会话」绑定：用户退出应用 / 手动锁定 / 超时后必须调用
 * [destroy] 清零。本类不实现 Serializable，不允许被写入磁盘或持久化。
 */
class MasterKeyMaterial(
    /** 数据加密密钥（DEK）明文，仅存在于内存。 */
    val dataKey: ByteArray,
    val keyId: String,
    /** 信封快照，用于在修改主密码时复用同一把 DEK。 */
    val envelope: KeyEnvelope,
) {
    /** 字段加密子密钥（用途隔离，与 MAC 子密钥不同）。 */
    val fieldKey: ByteArray by lazy { CryptoPrimitives.deriveSubKey(dataKey, LABEL_FIELD) }

    /** 库级完整性 MAC 子密钥。 */
    val macKey: ByteArray by lazy { CryptoPrimitives.deriveSubKey(dataKey, LABEL_MAC) }

    /** 备份文件加密子密钥。 */
    val backupKey: ByteArray by lazy { CryptoPrimitives.deriveSubKey(dataKey, LABEL_BACKUP) }

    /** 用于派生「自动填充索引」的确定性哈希子密钥（避免明文存储站点名）。 */
    val indexKey: ByteArray by lazy { CryptoPrimitives.deriveSubKey(dataKey, LABEL_INDEX) }

    fun destroy() {
        CryptoPrimitives.destroy(dataKey, fieldKey, macKey, backupKey, indexKey)
    }

    companion object {
        private const val LABEL_FIELD = "myvault/v1/field-encryption"
        private const val LABEL_MAC = "myvault/v1/vault-integrity"
        private const val LABEL_BACKUP = "myvault/v1/backup-encryption"
        private const val LABEL_INDEX = "myvault/v1/search-index"

        const val MAC_LABEL = "myvault/v1/envelope-mac"
    }
}
