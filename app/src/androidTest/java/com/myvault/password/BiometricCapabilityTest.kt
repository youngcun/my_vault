package com.myvault.password

import androidx.biometric.BiometricManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import com.myvault.password.core.BiometricCapability
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 设备生物识别能力探测测试。
 *
 * 背景：本应用曾在只有 Class 2（弱）生物识别的设备上尝试做加密绑定，系统报
 * `Crypto-based authentication is not supported for Class 2 (Weak) biometrics`。
 * 更隐蔽的一种情况是：设备**同时**支持 STRONG 与 WEAK，若提示框把两者都允许，
 * 系统可能选择 WEAK（例如人脸），导致绑定同样失败 —— 用户看到的就是
 * 「指纹解锁打不开」。因此必须断言：
 *
 * **只要设备支持 Class 3 生物识别，本应用就必须只请求 Class 3，绝不把 WEAK 一起允许。**
 *
 * 这条不变量是修复「指纹打不开」的核心，因此写成断言而不是打印。
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class BiometricCapabilityTest {

    private val context get() = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun resolveAlwaysPrefersStrongBiometricsWhenAvailable() {
        val manager = BiometricManager.from(context)
        val strongAvailable =
            manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS

        val config = BiometricCapability.resolve(context)
        assertNotNull(config)

        if (strongAvailable) {
            // 核心不变量：有 Class 3 就只用 Class 3
            assertEquals(
                "设备支持 Class 3 生物识别时必须选用它",
                BiometricCapability.Authenticator.BIOMETRIC_STRONG,
                config.authenticator,
            )
            assertEquals(
                "提示框只能允许 BIOMETRIC_STRONG，绝不能把 WEAK 一起允许 —— " +
                    "否则系统可能选到 Class 2 而导致加密绑定失败",
                BiometricManager.Authenticators.BIOMETRIC_STRONG,
                config.allowedAuthenticators,
            )
            assertTrue("Class 3 必须支持加密绑定", config.supportsCryptoObject)
            assertFalse(config.weakBiometricsOnly)
        } else {
            // 没有 Class 3 时不允许「假装可用」：要么回退到设备凭据，要么明确不可用
            assertTrue(
                "无 Class 3 时只能是设备凭据或不可用",
                config.authenticator == BiometricCapability.Authenticator.DEVICE_CREDENTIAL ||
                    config.authenticator == BiometricCapability.Authenticator.NONE,
            )
            if (!config.supportsCryptoObject) {
                assertTrue(
                    "不可用时必须能区分「只有弱生物识别」这一原因，以便给出准确提示",
                    config.weakBiometricsOnly ||
                        config.authenticator == BiometricCapability.Authenticator.NONE,
                )
            }
        }
    }

    /**
     * 断言：绝不能把 `BIOMETRIC_WEAK` 作为允许的认证方式。
     *
     * 注意位掩码的坑：`BIOMETRIC_WEAK = 0x00FF` 在**数值上包含**
     * `BIOMETRIC_STRONG = 0x0001`，因此 `(allowed and WEAK) != 0` 会假阳性 ——
     * 这是编写这类断言时最容易犯的错误。正确的判定是「不等于 WEAK 本身」。
     */
    @Test
    fun neverAllowsWeakBiometricsAsAuthenticator() {
        val config = BiometricCapability.resolve(context)
        assertTrue(
            "allowedAuthenticators 不得等于 BIOMETRIC_WEAK（那会让系统选到 Class 2，" +
                "从而出现 Crypto-based authentication is not supported for Class 2）",
            config.allowedAuthenticators != BiometricManager.Authenticators.BIOMETRIC_WEAK,
        )
        // 若声称支持加密绑定，则允许的认证方式必须是 STRONG 与/或 DEVICE_CREDENTIAL
        if (config.supportsCryptoObject) {
            val allowed = config.allowedAuthenticators
            val validCombination = allowed == BiometricManager.Authenticators.BIOMETRIC_STRONG ||
                allowed == (BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            assertTrue(
                "支持加密绑定时 allowedAuthenticators=0x${allowed.toString(16)} 不是合法组合",
                validCombination,
            )
        }
    }

    /** 使用设备凭据时不得设置 negative button（否则 BiometricPrompt 会抛异常）。 */
    @Test
    fun promptInfoIsBuildableForResolvedConfig() {
        val config = BiometricCapability.resolve(context)
        if (!config.isAvailable) return

        // 能构造出来即说明 allowedAuthenticators 与 negative button 的组合合法
        val info = BiometricCapability.buildPromptInfo(
            config = config,
            title = "t",
            subtitle = "s",
            negativeButtonText = "cancel",
        )
        assertNotNull(info)
    }
}
