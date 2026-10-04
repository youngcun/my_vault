package com.myvault.password.core

/**
 * Base64 编解码。
 *
 * 使用 java.util.Base64（JDK 8+ / Android 8+ 均可用）而不是 android.util.Base64，
 * 目的是让加密内核可以在纯 JVM 单元测试里直接运行 —— 与 Android 运行时解耦后，
 * 密码学逻辑才可能被自动化测试真正覆盖。
 */
object Base64Codec {

    private val encoder: java.util.Base64.Encoder = java.util.Base64.getEncoder()
    private val decoder: java.util.Base64.Decoder = java.util.Base64.getDecoder()
    private val urlEncoder: java.util.Base64.Encoder = java.util.Base64.getUrlEncoder().withoutPadding()
    private val urlDecoder: java.util.Base64.Decoder = java.util.Base64.getUrlDecoder()

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    fun decode(text: String): ByteArray = decoder.decode(text)

    fun encodeUrl(bytes: ByteArray): String = urlEncoder.encodeToString(bytes)

    fun decodeUrl(text: String): ByteArray = urlDecoder.decode(text)
}
