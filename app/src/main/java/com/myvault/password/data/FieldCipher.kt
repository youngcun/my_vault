package com.myvault.password.data

import com.myvault.password.core.Base64Codec
import com.myvault.password.core.CryptoPrimitives
import com.myvault.password.core.MasterKeyMaterial
import com.myvault.password.domain.VaultEntry

/**
 * 字段级加解密。
 *
 * AAD 的设计是这一层的核心
 * ----------------------
 * 每条密文的附加认证数据固定为：
 *
 * ```
 *   "myvault-field|v1|<entryId>|<fieldName>"
 * ```
 *
 * 这让密文与「它属于哪条记录的哪个字段」在密码学上绑定。因此：
 *  - 把 A 条目的密码密文复制到 B 条目的密码列 → 解密失败（entryId 不同）；
 *  - 把密码密文挪到用户名列 → 解密失败（fieldName 不同）；
 *  - 攻击者若能写数据库文件（例如通过某个文件写入漏洞），也无法凭空
 *    构造出「看似合法」的条目，因为他没有字段子密钥。
 *
 * 注意：本类不解密失败时返回空串 —— 那样会静默掩盖篡改。
 * 一律抛异常，由上层决定如何呈现。
 */
class FieldCipher(private val material: MasterKeyMaterial) {

    enum class Field(val column: String) {
        SITE("site"),
        USERNAME("username"),
        PASSWORD("password"),
        URL("url"),
        NOTES("notes"),
    }

    private fun aad(entryId: String, field: Field): ByteArray =
        "myvault-field|v1|$entryId|${field.column}".toByteArray(Charsets.UTF_8)

    fun encrypt(entryId: String, field: Field, plaintext: String): String {
        // 空字符串同样加密：保持「所有字段都是密文」这一不变量，
        // 避免通过「该列为空」推断出用户没填某个字段。
        val ct = CryptoPrimitives.aesGcmEncrypt(
            material.fieldKey,
            plaintext.toByteArray(Charsets.UTF_8),
            aad(entryId, field),
        )
        return Base64Codec.encode(ct)
    }

    fun decrypt(entryId: String, field: Field, ciphertext: String): String {
        val ct = try {
            Base64Codec.decode(ciphertext)
        } catch (e: IllegalArgumentException) {
            throw CorruptEntryException("条目 $entryId 的 ${field.column} 字段不是合法 Base64", e)
        }
        val pt = try {
            CryptoPrimitives.aesGcmDecrypt(material.fieldKey, ct, aad(entryId, field))
        } catch (e: Exception) {
            throw CorruptEntryException(
                "条目 $entryId 的 ${field.column} 字段解密失败（可能被篡改或密钥不匹配）", e,
            )
        }
        return String(pt, Charsets.UTF_8)
    }

    /** 明文条目 → 数据库中加密后的形态。 */
    fun toEntity(entry: VaultEntry): EntryEntity = EntryEntity(
        id = entry.id,
        siteEnc = encrypt(entry.id, Field.SITE, entry.site),
        usernameEnc = encrypt(entry.id, Field.USERNAME, entry.username),
        passwordEnc = encrypt(entry.id, Field.PASSWORD, entry.password),
        urlEnc = encrypt(entry.id, Field.URL, entry.url),
        notesEnc = encrypt(entry.id, Field.NOTES, entry.notes),
        fav = entry.favorite,
        generated = entry.generated,
        createdAt = entry.createdAt,
        updatedAt = entry.updatedAt,
    )

    /** 数据库形态 → 明文条目。任一步解密失败都会抛出 [CorruptEntryException]。 */
    fun fromEntity(entity: EntryEntity): VaultEntry = VaultEntry(
        id = entity.id,
        site = decrypt(entity.id, Field.SITE, entity.siteEnc),
        username = decrypt(entity.id, Field.USERNAME, entity.usernameEnc),
        password = decrypt(entity.id, Field.PASSWORD, entity.passwordEnc),
        url = decrypt(entity.id, Field.URL, entity.urlEnc),
        notes = decrypt(entity.id, Field.NOTES, entity.notesEnc),
        favorite = entity.fav,
        generated = entity.generated,
        createdAt = entity.createdAt,
        updatedAt = entity.updatedAt,
    )
}

/** 条目密文损坏或无法解密。 */
class CorruptEntryException(message: String, cause: Throwable? = null) : Exception(message, cause)
