package com.myvault.password.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * 数据访问对象。
 *
 * 设计原则：**DAO 层只碰密文与明文元数据，永远不接触密钥**。
 * 解密统一发生在 [VaultRepository] 里，那里才有 [com.myvault.password.core.MasterKeyMaterial]。
 * 这样即使有人误用 DAO，也不会绕过解密路径直接写出明文。
 */
@Dao
interface VaultDao {

    // ------------------------------------------------------------ 条目

    /** 监听全部条目（按更新时间倒序）。Room 会在表变化时自动重新发射。 */
    @Query("SELECT * FROM entries ORDER BY fav DESC, updated_at DESC")
    fun observeAll(): Flow<List<EntryEntity>>

    @Query("SELECT * FROM entries ORDER BY fav DESC, updated_at DESC")
    suspend fun loadAll(): List<EntryEntity>

    @Query("SELECT * FROM entries WHERE id = :id LIMIT 1")
    suspend fun loadById(id: String): EntryEntity?

    @Query("SELECT COUNT(*) FROM entries")
    suspend fun count(): Int

    /** 供完整性校验使用：拿全部密文，不解密。 */
    @Query("SELECT * FROM entries")
    suspend fun loadAllForIntegrity(): List<EntryEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entry: EntryEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<EntryEntity>)

    @Query("DELETE FROM entries WHERE id = :id")
    suspend fun deleteById(id: String)

    @Query("DELETE FROM entries")
    suspend fun deleteAll()

    @Query("UPDATE entries SET fav = :fav, updated_at = :updatedAt WHERE id = :id")
    suspend fun setFavorite(id: String, fav: Boolean, updatedAt: Long)

    // ------------------------------------------------------------ 密钥信封

    @Query("SELECT * FROM key_envelope WHERE id = ${EnvelopeEntity.SINGLETON_ID} LIMIT 1")
    suspend fun loadEnvelope(): EnvelopeEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveEnvelope(envelope: EnvelopeEntity)

    // ------------------------------------------------------------ 元数据

    @Query("SELECT * FROM vault_meta WHERE id = ${VaultMetaEntity.SINGLETON_ID} LIMIT 1")
    suspend fun loadMeta(): VaultMetaEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveMeta(meta: VaultMetaEntity)

    @Query("DELETE FROM vault_meta")
    suspend fun clearMeta()
}
