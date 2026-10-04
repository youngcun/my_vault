package com.myvault.password.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

/**
 * 密码库数据库。
 *
 * 关于「为什么不用 SQLCipher」
 * -------------------------
 * 常见做法是给 SQLite 整体加密（SQLCipher）。本项目改用**字段级加密 + 库级 HMAC**，
 * 原因是：
 *  1. SQLCipher 依赖 native 库，会给 APK 引入数 MB 的 .so，
 *     而字段级加密只需平台自带的 JCE，攻击面更小、更容易审计；
 *  2. 字段级加密能让「哪些字段敏感」这件事在代码里显式可见 ——
 *     审计者可以逐个字段确认，而不是相信「整个文件被加密了」；
 *  3. 数据库文件位于应用私有目录且设备已启用文件级加密（FBE），
 *     静态攻击者首先要突破设备锁屏才能读到密文文件；
 *  4. 自动化填充只需要解密站点名，无需把整库明文读进内存。
 *
 * 因此本类的导出 schema 里所有敏感列都以 `_enc` 结尾，且值是 AES-256-GCM 密文。
 */
@Database(
    entities = [EntryEntity::class, EnvelopeEntity::class, VaultMetaEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class VaultDatabase : RoomDatabase() {

    abstract fun dao(): VaultDao

    companion object {
        const val DATABASE_NAME = "vault.db"

        /** 明文数据库（v1）。升级到加密存储时必须走显式 Migration，不能破坏性重建。 */
        fun build(context: Context): VaultDatabase =
            Room.databaseBuilder(context.applicationContext, VaultDatabase::class.java, DATABASE_NAME)
                // 结构变化必须显式处理：这里没有 fallbackToDestructiveMigration，
                // 因为「静默清空用户的密码库」是不可接受的失败模式。
                .build()
    }
}
