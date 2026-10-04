package com.myvault.password.core

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt

/**
 * 设备可用的「解锁方式」能力探测。
 *
 * 为什么需要这个类
 * --------------
 * Android 的生物识别按强度分为两类（对应 NIST SP 800-63B 的分级）：
 *
 *  - **Class 3 / `BIOMETRIC_STRONG`**：指纹、3D 结构光人脸。可与人脸/指纹一起用于
 *    **加密绑定**（`CryptoObject`），因为伪造难度足够高；
 *  - **Class 2 / `BIOMETRIC_WEAK`**：大多数 2D 人脸识别（例如 MIUI 的人脸解锁）。
 *    **不能**用于加密绑定。
 *
 * 这一点在平台 API 上是硬约束：`KeyProperties` 里**根本不存在**
 * `AUTH_BIOMETRIC_WEAK` 常量，只有 `AUTH_BIOMETRIC_STRONG` 与 `AUTH_DEVICE_CREDENTIAL`。
 * 也就是说，「用弱生物识别保护一把密钥」在系统层面就是不可能的。
 * 强行尝试的结果是运行期报错：
 * `Crypto-based authentication is not supported for Class 2 (Weak) biometrics`。
 *
 * 本应用曾经把密钥强度写死为 STRONG，同时在 BiometricPrompt 里允许 WEAK，
 * 于是出现了一个很难察觉的组合：**弹窗验证通过、但随后的 CryptoObject 绑定失败**，
 * 用户看到的就是「指纹解锁打不开」。现在改为先探测、再据此决定可用性，
 * 并且**在没有可加密绑定的认证方式时明确拒绝**，而不是假装成功。
 *
 * 关于 `canAuthenticate` 的语义
 * --------------------------
 * 其行为由入参 `authenticators` 的**位数**决定：
 * 传 1 位（如仅 STRONG）→ 检查「是否至少注册了该类的任意一个」；
 * 传多位 → 检查该位掩码组合是否可用。
 */
object BiometricCapability {

    /** 本应用可用于**加密绑定**的认证方式。 */
    enum class Authenticator {
        /** Class 3 生物识别（指纹 / 3D 人脸）。 */
        BIOMETRIC_STRONG,

        /** 设备凭据（PIN / 图案 / 密码）。Android 11+ 才支持加密绑定。 */
        DEVICE_CREDENTIAL,

        /** 没有任何可用于加密绑定的解锁方式。 */
        NONE,
    }

    /** 解析结果。 */
    data class PromptConfig(
        val authenticator: Authenticator,
        /** 传给 `PromptInfo.setAllowedAuthenticators` 的位掩码。 */
        val allowedAuthenticators: Int,
        /**
         * 是否可以把 Cipher 交给 BiometricPrompt 做加密绑定。
         *
         * 为 false 时本应用会**拒绝**开启指纹解锁并说明原因 ——
         * 绝不用「不需要加密绑定的认证」假装成功，因为那并不能真正保护数据。
         */
        val supportsCryptoObject: Boolean,
        /** 设备只提供 Class 2（弱）生物识别。用于给出针对性的解释。 */
        val weakBiometricsOnly: Boolean,
    ) {
        val isAvailable: Boolean get() = authenticator != Authenticator.NONE
    }

    /**
     * 探测设备能力。
     *
     * @param preferBiometric true 表示优先使用生物识别（本应用的主路径）。
     */
    fun resolve(context: Context, preferBiometric: Boolean = true): PromptConfig {
        val manager = BiometricManager.from(context)

        if (preferBiometric &&
            canAuthenticate(manager, BiometricManager.Authenticators.BIOMETRIC_STRONG)
        ) {
            return PromptConfig(
                authenticator = Authenticator.BIOMETRIC_STRONG,
                allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG,
                supportsCryptoObject = true,
                weakBiometricsOnly = false,
            )
        }

        // 设备只注册了 Class 2 生物识别？记录这一事实，用于给出准确提示。
        val hasWeakOnly = preferBiometric &&
            canAuthenticate(manager, BiometricManager.Authenticators.BIOMETRIC_WEAK)

        // 设备凭据回退：Android 11+ 支持与密钥绑定（时效 0），
        // Android 10 及以下不支持 —— 那时直接视为不可用。
        val deviceCredentialOk = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
            canAuthenticate(manager, BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        if (deviceCredentialOk) {
            return PromptConfig(
                authenticator = Authenticator.DEVICE_CREDENTIAL,
                // 使用 DEVICE_CREDENTIAL 时必须同时允许一种生物识别作为回退，
                // 这是 BiometricPrompt 的强制要求。
                allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                supportsCryptoObject = true,
                weakBiometricsOnly = false,
            )
        }

        return PromptConfig(
            authenticator = Authenticator.NONE,
            allowedAuthenticators = 0,
            supportsCryptoObject = false,
            weakBiometricsOnly = hasWeakOnly,
        )
    }

    /**
     * 构造 PromptInfo。
     *
     * 硬性约束：使用 `DEVICE_CREDENTIAL` 时**不能**设置 negative button
     * （系统自带「使用 PIN/密码」入口），否则抛异常。
     */
    fun buildPromptInfo(
        config: PromptConfig,
        title: String,
        subtitle: String,
        negativeButtonText: String,
    ): BiometricPrompt.PromptInfo {
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(config.allowedAuthenticators)

        val allowsDeviceCredential =
            (config.allowedAuthenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL) != 0
        if (!allowsDeviceCredential) {
            builder.setNegativeButtonText(negativeButtonText)
        }
        return builder.build()
    }

    private fun canAuthenticate(manager: BiometricManager, authenticators: Int): Boolean = try {
        manager.canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
    } catch (e: Exception) {
        // 某些 ROM 对不支持的组合会抛异常，按「不可用」处理
        false
    }
}
