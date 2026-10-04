package com.myvault.password

import android.content.Context
import androidx.room.Room
import com.myvault.password.backup.BackupManager
import com.myvault.password.core.AutoLockSession
import com.myvault.password.core.PasswordGenerator
import com.myvault.password.data.VaultDao
import com.myvault.password.data.VaultDatabase
import com.myvault.password.data.VaultRepository
import com.myvault.password.operationlog.VaultOperationLog
import com.myvault.password.settings.SettingsStore
import java.io.File

/**
 * 应用级依赖容器。
 *
 * 为什么手写容器而不是引入 Hilt / Koin：
 *  - 依赖图非常小（对象只有个位数），手写更透明、可审计；
 *  - 注入框架会在 APK 里生成额外的类和反射元数据，扩大攻击面；
 *  - 「密码库应用不应该引入一个需要注解处理器的 DI 框架」——
 *    依赖越少，第三方代码越少，用户越容易相信这个 APK。
 *
 * 生命周期与 Application 一致。注意：[VaultRepository] 内部的密钥材料
 * 是**会话级**的，会随 [VaultRepository.lock] 清零，与本容器无关。
 */
class AppContainer(private val context: Context) {

    /** Room 数据库。使用单例，避免多实例同时打开同一文件。 */
    val database: VaultDatabase by lazy {
        Room.databaseBuilder(
            context.applicationContext,
            VaultDatabase::class.java,
            VaultDatabase.DATABASE_NAME,
        )
            // 本项目不提供破坏性迁移：宁可让用户看到明确报错，
            // 也不能在升级时静默清空他的密码库。
            .build()
    }

    val dao: VaultDao by lazy { database.dao() }

    val repository: VaultRepository by lazy { VaultRepository(dao) }

    val settings: SettingsStore by lazy { SettingsStore(context.applicationContext) }

    val backupManager: BackupManager by lazy { BackupManager() }

    /**
     * 操作日志（最近 30 天的重要操作）。
     *
     * 与数据库分开存放：日志是旁路数据，它的格式变化不该迫使密码库写 Room 迁移，
     * 也不该和「用户的密码」共用同一条崩溃恢复路径。日志不含任何凭据，
     * 因此明文存于应用私有目录（受设备文件级加密保护）是可以接受的。
     */
    val operationLog: VaultOperationLog by lazy {
        VaultOperationLog(File(context.applicationContext.filesDir, VaultOperationLog.FILE_NAME))
    }

    /** 生成器本身无状态（随机源由平台 CSPRNG 提供），共享一个实例即可。 */
    val passwordGenerator: PasswordGenerator by lazy { PasswordGenerator() }

    /**
     * 自动锁定的会话状态。
     *
     * 放在容器（而不是 ViewModel）里的原因：**Activity 也需要它**。
     * SAF 文件选择器与备份文件的读写都由 Activity 发起，而 Activity 拿不到
     * 导航作用域里的 `MainViewModel` —— 此前为此加了一条「组合期注册的回调桥」，
     * 那条桥自己出了问题（第一次导出后引用被置空，第二次导出失去豁免而在选择
     * 文件时被锁定）。现在双方直接读写同一份状态，不再需要中间层。
     *
     * 它不持有任何秘密，只有一个时间戳和若干原因名，因此放在应用级容器里是安全的。
     */
    val autoLockSession: AutoLockSession by lazy { AutoLockSession() }

    companion object {
        fun from(context: Context): AppContainer {
            val app = context.applicationContext as VaultApplication
            return app.container
        }
    }
}
