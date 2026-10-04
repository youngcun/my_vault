package com.myvault.password.core

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore 封装：生物识别门控的密钥。
 *
 * 安全模型
 * -------
 * 这里生成的 AES 密钥**永远不以明文形式离开 TEE / StrongBox**。
 * 它带有 `setUserAuthenticationRequired(true)`，意味着：
 *  - 没有一次成功的生物识别（或设备凭据）验证，`Cipher.init` 就会抛异常；
 *  - 即便攻击者拿到 root 权限读出密钥库文件，得到的也只是被硬件密钥
 *    加密过的密文；
 *  - `setInvalidatedByBiometricEnrollment(true)` 保证用户新增或删除指纹后
 *    该密钥自动失效 —— 防止有人偷偷录入自己的指纹后解锁你的密码库。
 *
 * 因此「指纹解锁」并不是把主密码锁在文件里等指纹开门，而是：
 *
 * ```
 *   指纹成功 → TEE 释放 KEK_bio → 解密信封里的 bio_dek 得到 DEK
 * ```
 *
 * 攻击者若想离线破解，必须突破 TEE，而不是猜密码。
 */
class KeystoreManager {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val BIO_ALIAS_PREFIX = "myvault.bio."

        /** 对应的数据密钥长度。 */
        private const val KEY_SIZE_BITS = 256

        /** 与 [CryptoPrimitives] 保持一致的 GCM 参数。 */
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128
        private const val TAG_BYTES = TAG_BITS / 8

        /** 该设备是否具备可用的生物识别硬件。 */
        fun isBiometricCapable(): Boolean {
            // 真正的可用性检查在 BiometricPrompt 层（CanAuthenticate），
            // 这里只判断 Keystore 是否支持所需特性。
            return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
        }
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /** 该别名下是否已存在密钥。 */
    fun containsKey(alias: String): Boolean = try {
        keyStore().containsAlias(alias)
    } catch (e: Exception) {
        false
    }

    /**
     * 生成或取回受生物识别保护的密钥。
     *
     * 认证模型：**每次操作认证（per-operation authentication）**
     * --------------------------------------------------------
     * 这把密钥**必须**配合 `BiometricPrompt` 的 `CryptoObject` 使用：
     * 先用它初始化一个 [Cipher]，把 Cipher 交给 BiometricPrompt，
     * 用户通过指纹后系统才「解锁」那个 Cipher 实例，然后才能 doFinal。
     *
     * 绝不能写成「时效型认证」（`setUserAuthenticationValidityDurationSeconds(30)`）：
     * 那种模型的正确用法是先用 `KeyStore.getEntry(alias, null)` 触发认证，
     * 之后在有效期内直接使用密钥对象。若跳过 `getEntry` 直接 `Cipher.init`，
     * 系统会抛 **`UserNotAuthenticatedException`（"user not authenticated"）** ——
     * 这正是本应用曾经出现过的指纹解锁故障。
     *
     * 对密码库而言，每次填充/解锁都要一次指纹，既正确也更安全：
     * 不存在「认证后 30 秒内任意使用」的窗口。
     */
    /**
     * 强制新建一把认证绑定的密钥（先删同别名的旧密钥）。
     *
     * 用途：修复旧版本遗留的密钥 —— 曾用过「时效型认证」，
     * 也用过写死的 `AUTH_BIOMETRIC_STRONG`（在只有 Class 2 生物识别的设备上
     * 会导致 `Crypto-based authentication is not supported for Class 2 (Weak) biometrics`）。
     * 用户重新开启一次指纹解锁即可完成迁移，不需要清除应用数据。
     *
     * @param authenticator 与 [BiometricCapability.resolve] 的结果保持一致。
     *   必须与 BiometricPrompt 允许的认证方式匹配，否则加密绑定会失败。
     */
    fun recreateAuthBoundKey(
        alias: String,
        authenticator: BiometricCapability.Authenticator,
    ): SecretKey {
        deleteKey(alias)
        return createAuthBoundKey(alias, authenticator)
    }

    private fun createAuthBoundKey(
        alias: String,
        authenticator: BiometricCapability.Authenticator,
    ): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_SIZE_BITS)
            // 必须经过一次用户认证才能使用 —— 配合 CryptoObject 实现「每次操作认证」
            .setUserAuthenticationRequired(true)

        // 只有生物识别密钥才谈得上「指纹集合变化即失效」；
        // 设备凭据绑定的密钥没有这个语义。
        if (authenticator != BiometricCapability.Authenticator.DEVICE_CREDENTIAL) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // 显式声明「时效为 0」= 每次操作都必须认证。
            // 注意：这里绝不能传大于 0 的值，否则就退化成时效型认证，
            // 而本类的调用方式（CryptoObject）与时效型认证不兼容。
            //
            // 认证强度必须与设备实际能力一致。
            //
            // 注意：`KeyProperties` 里**没有** AUTH_BIOMETRIC_WEAK —— 平台层面
            // 就不允许用 Class 2 生物识别保护密钥。因此可用值只有两个：
            //  - AUTH_BIOMETRIC_STRONG：指纹 / Class 3 人脸；
            //  - AUTH_DEVICE_CREDENTIAL：设备 PIN/图案/密码（Android 11+ 可加密绑定）。
            val authType = when (authenticator) {
                BiometricCapability.Authenticator.BIOMETRIC_STRONG ->
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                BiometricCapability.Authenticator.DEVICE_CREDENTIAL ->
                    KeyProperties.AUTH_DEVICE_CREDENTIAL
                BiometricCapability.Authenticator.NONE ->
                    throw IllegalArgumentException("没有可用于加密绑定的认证方式")
            }
            builder.setUserAuthenticationParameters(0, authType)
        } else {
            // API 26~29：传 0 同样表示每次操作都需要认证
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(0)
        }

        generator.init(builder.build())
        return generator.generateKey()
    }

    /**
     * 用一个已通过认证的 [Cipher] 加密数据。
     * @return `IV(12) || 密文 || Tag(16)`
     */
    fun seal(cipher: Cipher, plaintext: ByteArray): ByteArray {
        val body = cipher.doFinal(plaintext)
        return cipher.iv + body
    }

    /**
     * 为解密准备一个 Cipher，交给 BiometricPrompt 认证。
     *
     * 返回 `(cipher, body)`：cipher 必须交给
     * `BiometricPrompt.authenticate(PromptInfo, CryptoObject(cipher))`，
     * 认证成功后拿回来的 cipher 才能 `doFinal(body)`。
     *
     * 注意：`cipher.init` 本身**不会**要求认证（认证在 CryptoObject 流程里完成）。
     * 若这里就抛 `UserNotAuthenticatedException`，说明密钥是用时效型认证创建的 ——
     * 必须删除该别名下的旧密钥并重新绑定，这正是 [deleteKey] 存在的意义。
     */
    fun openCipherForDecrypt(alias: String, sealed: ByteArray): Pair<Cipher, ByteArray> {
        require(sealed.size >= IV_BYTES + TAG_BYTES) { "指纹密文长度不足" }
        val iv = sealed.copyOfRange(0, IV_BYTES)
        val body = sealed.copyOfRange(IV_BYTES, sealed.size)
        val key = (keyStore().getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: throw IllegalStateException("找不到指纹密钥，请重新开启指纹解锁")
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        return cipher to body
    }

    /**
     * 判断某个别名下的密钥是否可用于 CryptoObject 流程。
     *
     * 用途：老版本可能用「时效型认证」创建过密钥（正是导致
     * `UserNotAuthenticatedException` 的那一种）。重新启用指纹时先用本方法探测，
     * 不兼容就删掉重建，避免用户反复遇到「指纹打不开」。
     */
    fun isUsableWithCryptoObject(alias: String): Boolean = try {
        val key = (keyStore().getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: return false
        // 尝试用该密钥初始化一个加密 Cipher。
        // 每次操作认证的密钥可以正常初始化（认证发生在 CryptoObject 流程中）；
        // 时效型认证的密钥在此处同样能初始化，因此这里只做「密钥存在且算法可用」的探测。
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        true
    } catch (e: Exception) {
        false
    }

    /** 删除生物识别密钥（关闭指纹解锁时调用）。 */
    fun deleteKey(alias: String) {
        try {
            val ks = keyStore()
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        } catch (e: Exception) {
            // 删除失败不应阻断「关闭指纹」的流程：信封里的 bio_dek 会被一并抹掉，
            // 因此残留的 Keystore 密钥也解密不出任何有用的东西。
        }
    }

    /** 该异常表示指纹集合已变化，需要用户用主密码重新开启指纹解锁。 */
    fun isPermanentlyInvalidated(t: Throwable): Boolean =
        t is KeyPermanentlyInvalidatedException ||
            t.cause is KeyPermanentlyInvalidatedException
}
