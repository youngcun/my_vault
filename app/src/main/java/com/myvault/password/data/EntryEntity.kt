package com.myvault.password.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * 凭据条目（数据库中的形态）。
 *
 * 加密策略：**每个敏感字段单独加密**，而不是把整条记录序列化后加密。
 * 理由：
 *  1. 单字段加密允许按需解密（列表页只需站点名，不必在内存里暴露密码明文）；
 *  2. 每个字段的 AAD 里绑定了 `条目 ID + 字段名 + 版本号`，
 *     攻击者无法把「A 条目的密码密文」搬到「B 条目的用户名」位置上
 *     （这种「密文重排」攻击对整条加密的方案是有效的）；
 *  3. 元数据（[fav]、[createdAt]）明文存储，让列表排序与收藏筛选发生在 SQL 层，
 *     不必为了排序把所有记录解密进内存。
 *
 * 数据库文件本身位于应用私有目录，在 Android 10+ 上受
 * 文件级加密（FBE）保护；即便攻击者拿到磁盘镜像，还需要设备凭据才能读取。
 */
@Entity(
    tableName = "entries",
    indices = [
        Index(value = ["updated_at"]),
        Index(value = ["fav"]),
    ],
)
data class EntryEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,

    /** 加密后的站点 / 应用名称。 */
    @ColumnInfo(name = "site_enc")
    val siteEnc: String,

    /** 加密后的用户名 / 邮箱。 */
    @ColumnInfo(name = "username_enc")
    val usernameEnc: String,

    /** 加密后的密码。 */
    @ColumnInfo(name = "password_enc")
    val passwordEnc: String,

    /** 加密后的网址。 */
    @ColumnInfo(name = "url_enc")
    val urlEnc: String,

    /** 加密后的备注。 */
    @ColumnInfo(name = "notes_enc")
    val notesEnc: String,

    /** 是否收藏（明文，便于 SQL 层筛选）。 */
    @ColumnInfo(name = "fav", defaultValue = "0")
    val fav: Boolean = false,

    /**
     * 该条目密码是否为「应用生成」。明文存储不泄露密码内容，
     * 但能提示用户「这个密码是随机生成的」或「这是你自己设的旧密码」。
     */
    @ColumnInfo(name = "generated", defaultValue = "0")
    val generated: Boolean = false,

    @ColumnInfo(name = "created_at")
    val createdAt: Long,

    @ColumnInfo(name = "updated_at")
    val updatedAt: Long,
) {
    /** 全部字段的密文，用于计算库级校验和。 */
    fun ciphertexts(): List<String> =
        listOf(siteEnc, usernameEnc, passwordEnc, urlEnc, notesEnc)
}

/**
 * 密钥信封（数据库中的形态）。整张表**最多一行**。
 *
 * 把信封放在数据库里而不是 SharedPreferences，有两个考虑：
 *  1. 备份时天然被一起带走，不会出现「备份了数据却丢了密钥」的半残备份；
 *  2. 清除数据只需删一个文件，不存在两个存储位置不同步的问题。
 */
@Entity(tableName = "key_envelope")
data class EnvelopeEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: Int = SINGLETON_ID,

    /** KeyEnvelope 的规范 JSON 序列化结果。 */
    @ColumnInfo(name = "json")
    val json: String,

    @ColumnInfo(name = "updated_at")
    val updatedAt: Long = System.currentTimeMillis(),
) {
    companion object {
        const val SINGLETON_ID = 1
    }
}

/**
 * 库级元数据（单行）。
 *
 * [checksum] 是覆盖全库明文的 HMAC-SHA256。它的作用不是替代字段级 GCM，
 * 而是提供一种**可主动重跑**的完整性证据：用户可以在「安全自证」页面
 * 点击校验，立刻知道有没有任何一条记录被悄悄改写或损坏。
 */
@Entity(tableName = "vault_meta")
data class VaultMetaEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: Int = SINGLETON_ID,

    /** 已写入的唯一 ID 计数器，用于生成人类可读的编号（当前未使用，保留扩展）。 */
    @ColumnInfo(name = "schema_version")
    val schemaVersion: Int = CURRENT_SCHEMA_VERSION,

    /** 覆盖全库内容与密文的 HMAC-SHA256（Base64）。null 表示尚未计算。 */
    @ColumnInfo(name = "checksum")
    val checksum: String? = null,

    /** 上次成功校验的时间。 */
    @ColumnInfo(name = "last_verified_at")
    val lastVerifiedAt: Long? = null,

    /** 上一次校验发现的问题条数（0 表示全部通过）。 */
    @ColumnInfo(name = "last_bad_count")
    val lastBadCount: Int = 0,
) {
    companion object {
        const val SINGLETON_ID = 1
        const val CURRENT_SCHEMA_VERSION = 1
    }
}
