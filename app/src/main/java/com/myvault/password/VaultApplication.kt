package com.myvault.password

import android.app.Application
import com.myvault.password.core.LocaleController

/**
 * 应用入口。
 *
 * 这里刻意保持极简：**不在 Application.onCreate 里做任何密文库 IO、不做任何预热**。
 * 原因：进程可能在用户还没解锁时就被系统拉起（例如自动填充服务的绑定），
 * 此时绝不能触碰密文库文件 —— 少一次无用启动，就少一次密钥材料出现在
 * 内存里的机会。
 *
 * [container] 本身是惰性的，因此上面的承诺由「谁先访问谁触发」来保证：
 * 未解锁的自动填充路径不会访问 `repository`，也就不会打开数据库。
 *
 * [LocaleController.applyStored] 是这里唯一的启动期动作，它读的是一个
 * 只含语言标签的 SharedPreferences 文件，**不接触任何密文库数据**，
 * 因此不违背上面的承诺。放在这里的原因见 [LocaleController] 的说明：
 * 语言必须在第一个界面组合之前生效。
 */
class VaultApplication : Application() {

    val container: AppContainer by lazy { AppContainer(this) }

    override fun onCreate() {
        super.onCreate()
        LocaleController.applyStored(this)
    }
}
