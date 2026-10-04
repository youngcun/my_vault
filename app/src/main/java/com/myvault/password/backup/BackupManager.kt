package com.myvault.password.backup

import com.myvault.password.core.Base64Codec
import com.myvault.password.core.CryptoPrimitives
import com.myvault.password.core.Kdf
import com.myvault.password.domain.VaultEntry
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** 备份文件格式错误。 */
class BackupFormatException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** 备份口令错误。 */
class BackupPassphraseException(message: String = "备份口令错误，或备份文件已被篡改") : Exception(message)

/**
 * 加密备份：导出与导入。
 *
 * 文件格式（`MVBK1`）
 * -----------------
 * 备份是一个自包含的 JSON 文档 + 一个密文块：
 *
 * ```json
 * {
 *   "magic": "MyVaultBackup",
 *   "v": 1,
 *   "created_at": 1760000000000,
 *   "alg": "argon2id-aes256gcm",
 *   "salt": "<Base64>",
 *   "kdf_argon2": { "m": 65536, "t": 3, "p": 2 },
 *   "payload_enc": "<Base64(IV||密文||Tag)>",
 *   "mac": "<Base64(HMAC-SHA256)>",
 *   "entry_count": 42
 * }
 * ```
 *
 * 设计要点
 * -------
 * 1. **自包含**：KDF 参数与 salt 都写在文件头部，因此十年后即使本应用的
 *    Argon2 默认参数已经提高，旧文件依然可以被正确解开（参数随文件走）。
 * 2. **信封 MAC**：头部用口令派生的独立子密钥做 HMAC-SHA256。任何一个参数
 *    被改动（例如把迭代次数从 3 改成 1 以加速爆破）都会在解密前被发现。
 * 3. **AAD 绑定**：加密时把头部字段序列化后作为 AAD 传入 AES-GCM，
 *    使「头部与密文」在密码学上不可分离。
 * 4. **备份口令独立**：备份使用自己的口令（可以等于主密码，也可以不同）。
 *    这一点很重要 —— 备份文件通常会被放到 U 盘、NAS 或云盘，
 *    长期暴露在不受控的环境里；独立口令意味着即使备份文件泄露，
 *    主密码依然安全，攻击者也无法通过它反推你的主密码。
 * 5. 导入时完全**不信任**文件内容：先校验格式与大小上限，再校验 MAC，
 *    最后才解密。任何一步失败都不会触碰现有数据。
 */
class BackupManager(
    private val json: Json = Json {
        prettyPrint = true
        encodeDefaults = true
        ignoreUnknownKeys = true
    },
) {

    companion object {
        const val MAGIC = "MyVaultBackup"
        const val FORMAT_VERSION = 1

        /** 备份文件扩展名（仅用于建议文件名）。 */
        const val FILE_EXTENSION = "myvault"

        /** 导入大小上限：64 MiB。防止恶意构造的巨型文件耗尽内存。 */
        const val MAX_BACKUP_BYTES = 64L * 1024 * 1024

        /** 单次导入的条目数上限，防御性限制。 */
        const val MAX_ENTRIES = 100_000

        const val ALG_ARGON2ID = "argon2id-aes256gcm"
        const val ALG_PBKDF2 = "pbkdf2-aes256gcm"

        /**
         * 用途隔离标签：备份文件的加密子密钥与 MAC 子密钥必须不同。
         * 复用同一把密钥做「加密」和「完整性」会让两者的安全边界相互耦合。
         */
        private const val LABEL_ENC = "myvault/backup/v1/encryption"
        private const val LABEL_MAC = "myvault/backup/v1/integrity"

        /** 生成建议文件名，例如 `myvault-backup-20260101-120000.myvault`。 */
        fun suggestFileName(now: Long = System.currentTimeMillis()): String {
            val fmt = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.systemDefault())
            return "myvault-backup-${fmt.format(Instant.ofEpochMilli(now))}.$FILE_EXTENSION"
        }
    }

    // ------------------------------------------------------------ 格式定义

    @Serializable
    data class BackupEnvelope(
        @SerialName("magic") val magic: String = MAGIC,
        @SerialName("v") val version: Int = FORMAT_VERSION,
        @SerialName("created_at") val createdAt: Long,
        @SerialName("app_version") val appVersion: String,
        @SerialName("alg") val algorithm: String,
        @SerialName("salt") val salt: String,
        @SerialName("kdf_argon2") val argon2: Kdf.Argon2Params? = null,
        @SerialName("kdf_pbkdf2") val pbkdf2: Kdf.Pbkdf2Params? = null,
        @SerialName("entry_count") val entryCount: Int,
        @SerialName("payload_enc") val payloadEnc: String,
        @SerialName("mac") val mac: String,
    ) {
        /** 除 mac 与密文外的「头部」，用于计算 MAC 与 AAD。 */
        fun headerForMac(): BackupEnvelope = copy(mac = "", payloadEnc = "")
    }

    @Serializable
    data class BackupPayload(
        @SerialName("v") val version: Int = FORMAT_VERSION,
        @SerialName("exported_at") val exportedAt: Long,
        @SerialName("entries") val entries: List<BackupEntry>,
    )

    @Serializable
    data class BackupEntry(
        @SerialName("id") val id: String,
        @SerialName("site") val site: String = "",
        @SerialName("username") val username: String = "",
        @SerialName("password") val password: String = "",
        @SerialName("url") val url: String = "",
        @SerialName("notes") val notes: String = "",
        @SerialName("favorite") val favorite: Boolean = false,
        @SerialName("generated") val generated: Boolean = false,
        @SerialName("created_at") val createdAt: Long = 0,
        @SerialName("updated_at") val updatedAt: Long = 0,
    ) {
        fun toDomain(): VaultEntry = VaultEntry(
            id = id.ifBlank { java.util.UUID.randomUUID().toString() },
            site = site,
            username = username,
            password = password,
            url = url,
            notes = notes,
            favorite = favorite,
            generated = generated,
            createdAt = if (createdAt > 0) createdAt else System.currentTimeMillis(),
            updatedAt = if (updatedAt > 0) updatedAt else System.currentTimeMillis(),
        )

        companion object {
            fun fromDomain(e: VaultEntry) = BackupEntry(
                id = e.id,
                site = e.site,
                username = e.username,
                password = e.password,
                url = e.url,
                notes = e.notes,
                favorite = e.favorite,
                generated = e.generated,
                createdAt = e.createdAt,
                updatedAt = e.updatedAt,
            )
        }
    }

    // ------------------------------------------------------------ 导出

    /**
     * 导出加密备份。
     *
     * @param entries    要备份的条目（明文）
     * @param passphrase 备份口令（调用方负责用后清零）
     * @param appVersion 写入文件的应用版本，便于将来排查兼容性
     * @return 写入 [output] 的字节数
     */
    fun export(
        output: OutputStream,
        entries: List<VaultEntry>,
        passphrase: CharArray,
        appVersion: String,
        now: Long = System.currentTimeMillis(),
    ): Long {
        require(entries.size <= MAX_ENTRIES) { "导出条目数超过上限 $MAX_ENTRIES" }

        val payload = BackupPayload(
            exportedAt = now,
            entries = entries.map { BackupEntry.fromDomain(it) },
        )
        val payloadBytes = json.encodeToString(BackupPayload.serializer(), payload)
            .toByteArray(Charsets.UTF_8)

        val salt = Kdf.newSalt()
        val params = Kdf.Argon2Params()
        val kek = Kdf.deriveArgon2id(passphrase, salt, params)
        try {
            // 用途隔离：加密子密钥与 MAC 子密钥必须不同
            val encKey = CryptoPrimitives.deriveSubKey(kek, LABEL_ENC)
            val macKey = CryptoPrimitives.deriveSubKey(kek, LABEL_MAC)
            try {
                val skeleton = BackupEnvelope(
                    createdAt = now,
                    appVersion = appVersion,
                    algorithm = ALG_ARGON2ID,
                    salt = Base64Codec.encode(salt),
                    argon2 = params,
                    pbkdf2 = null,
                    entryCount = entries.size,
                    payloadEnc = "",
                    mac = "",
                )
                val aad = aadFor(skeleton)
                val ciphertext = CryptoPrimitives.aesGcmEncrypt(encKey, payloadBytes, aad)
                val withPayload = skeleton.copy(payloadEnc = Base64Codec.encode(ciphertext))
                val mac = CryptoPrimitives.hmacSha256(macKey, macInput(withPayload))
                val sealed = withPayload.copy(mac = Base64Codec.encode(mac))
                val text = json.encodeToString(BackupEnvelope.serializer(), sealed)
                val bytes = text.toByteArray(Charsets.UTF_8)
                output.write(bytes)
                output.flush()
                return bytes.size.toLong()
            } finally {
                CryptoPrimitives.destroy(encKey, macKey)
            }
        } finally {
            CryptoPrimitives.destroy(kek)
            CryptoPrimitives.destroy(payloadBytes)
        }
    }

    // ------------------------------------------------------------ 导入

    /**
     * 读取并解密备份文件。
     *
     * @throws BackupFormatException     文件不是本应用的备份 / 结构损坏
     * @throws BackupPassphraseException 口令错误或文件被篡改
     */
    fun import(input: InputStream, passphrase: CharArray): List<VaultEntry> {
        val raw = readLimited(input)
        return importFromBytes(raw, passphrase)
    }

    /** 从内存字节导入（便于单元测试与 Robolectric 场景）。 */
    fun importFromBytes(raw: ByteArray, passphrase: CharArray): List<VaultEntry> {
        if (raw.size > MAX_BACKUP_BYTES) {
            throw BackupFormatException("备份文件过大（${raw.size} 字节），上限 $MAX_BACKUP_BYTES")
        }
        val text = String(raw, Charsets.UTF_8)
        val env = try {
            json.decodeFromString(BackupEnvelope.serializer(), text)
        } catch (e: Exception) {
            throw BackupFormatException("无法解析备份文件，可能不是本应用导出的文件", e)
        }

        if (env.magic != MAGIC) throw BackupFormatException("备份文件标识不匹配：${env.magic}")
        if (env.version > FORMAT_VERSION) {
            throw BackupFormatException("备份文件版本 ${env.version} 高于本应用支持的 $FORMAT_VERSION")
        }

        val salt = decodeOrThrow(env.salt, "salt")
        val kek = when (env.algorithm) {
            ALG_ARGON2ID -> {
                val p = env.argon2 ?: throw BackupFormatException("缺少 Argon2 参数")
                Kdf.deriveArgon2id(passphrase, salt, p)
            }
            ALG_PBKDF2 -> {
                val p = env.pbkdf2 ?: throw BackupFormatException("缺少 PBKDF2 参数")
                Kdf.derivePbkdf2(passphrase, salt, p)
            }
            else -> throw BackupFormatException("不支持的加密算法：${env.algorithm}")
        }

        try {
            val encKey = CryptoPrimitives.deriveSubKey(kek, LABEL_ENC)
            val macKey = CryptoPrimitives.deriveSubKey(kek, LABEL_MAC)
            try {
                // 第一道：头部 MAC —— 在解密之前就发现参数篡改
                val expectedMac = CryptoPrimitives.hmacSha256(macKey, macInput(env))
                val actualMac = decodeOrThrow(env.mac, "mac")
                if (!CryptoPrimitives.constantTimeEquals(expectedMac, actualMac)) {
                    throw BackupPassphraseException()
                }
                // 第二道：GCM 认证解密
                val ciphertext = decodeOrThrow(env.payloadEnc, "payload_enc")
                val payloadBytes = try {
                    CryptoPrimitives.aesGcmDecrypt(encKey, ciphertext, aadFor(env))
                } catch (e: Exception) {
                    throw BackupPassphraseException()
                }
                try {
                    val payload = try {
                        json.decodeFromString(BackupPayload.serializer(), String(payloadBytes, Charsets.UTF_8))
                    } catch (e: Exception) {
                        throw BackupFormatException("备份内容已损坏", e)
                    }
                    if (payload.entries.size > MAX_ENTRIES) {
                        throw BackupFormatException("备份条目数 ${payload.entries.size} 超过上限 $MAX_ENTRIES")
                    }
                    if (payload.entries.size != env.entryCount) {
                        // 不是致命错误（例如未来格式允许增量），但值得记录
                        // 这里选择严格校验：计数不符说明文件被改过
                        throw BackupFormatException(
                            "条目数与文件头声明不一致（头部 ${env.entryCount}，实际 ${payload.entries.size}）",
                        )
                    }
                    return payload.entries.map { it.toDomain() }
                } finally {
                    CryptoPrimitives.destroy(payloadBytes)
                }
            } finally {
                CryptoPrimitives.destroy(encKey, macKey)
            }
        } finally {
            CryptoPrimitives.destroy(kek)
            CryptoPrimitives.destroy(raw)
        }
    }

    // ------------------------------------------------------------ 内部工具

    private fun readLimited(input: InputStream): ByteArray {
        val buffer = ByteArrayOutputStream(64 * 1024)
        val chunk = ByteArray(16 * 1024)
        var total = 0L
        while (true) {
            val read = input.read(chunk)
            if (read < 0) break
            total += read
            if (total > MAX_BACKUP_BYTES) {
                throw BackupFormatException("备份文件超过大小上限 $MAX_BACKUP_BYTES 字节")
            }
            buffer.write(chunk, 0, read)
        }
        return buffer.toByteArray()
    }

    /** 头部（不含 mac 与密文）的规范化字节，用于 MAC 与 AAD。 */
    private fun headerBytes(env: BackupEnvelope): ByteArray =
        json.encodeToString(BackupEnvelope.serializer(), env.headerForMac()).toByteArray(Charsets.UTF_8)

    private fun macInput(env: BackupEnvelope): ByteArray = headerBytes(env)

    private fun aadFor(env: BackupEnvelope): ByteArray =
        ("myvault-backup-aad|" + headerBytes(env).toString(Charsets.UTF_8)).toByteArray(Charsets.UTF_8)

    private fun decodeOrThrow(text: String, field: String): ByteArray = try {
        Base64Codec.decode(text)
    } catch (e: IllegalArgumentException) {
        throw BackupFormatException("字段 $field 不是合法 Base64", e)
    }
}
