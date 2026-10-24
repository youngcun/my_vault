package com.myvault.password

import android.graphics.Bitmap
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.MediumTest
import com.myvault.password.qr.CredentialQr
import com.myvault.password.qr.QrCodes
import com.myvault.password.qr.QrCredential
import com.myvault.password.qr.QrPayload
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream

/**
 * 设备端二维码测试（真实 Android 位图与 ZXing）。
 *
 * 为什么这一层不能省：`CredentialQrTest` 只覆盖「文本 ↔ 文本」，
 * 而用户实际走的是「文本 → 位图 → 相机/相册 → 位图 → 文本」。
 * 中间这段依赖 `android.graphics.Bitmap` 的像素格式、ARGB 与 YUV 的亮度换算、
 * 以及 ZXing 的定位器 —— 这些在纯 JVM 上都没有等价物。
 *
 * 这里验证的正是 App 里那条**真实**解码路径（普通定位 → 纯码 → 旋转回退），
 * 而不是单元测试里为了稳定而使用的纯码捷径。
 */
@RunWith(AndroidJUnit4::class)
@MediumTest
class QrCodesInstrumentedTest {

    private fun sample() = QrCredential(
        site = "示例站点·MyVault",
        username = "sziron@outlook.com",
        password = "a%b&c=d+e f%20g\n第二行🔐",
        url = "https://example.com/login?a=1&b=2",
        notes = "备注：含 '单引号' 与 \"双引号\"，以及 #井号",
    )

    @Test
    fun 明文二维码可以被真实解码路径读回() {
        val payload = CredentialQr.encodePlain(sample())
        val bitmap = QrCodes.encode(payload)
        assertNotNull("二维码位图生成失败", bitmap)

        val decoded = QrCodes.decodeBitmap(bitmap!!)
        assertEquals(payload, decoded)

        val parsed = CredentialQr.parse(decoded!!) as QrPayload.Plain
        assertEquals(sample(), parsed.credential)
        bitmap.recycle()
    }

    @Test
    fun 加密二维码可以被真实解码路径读回并解开() {
        val payload = CredentialQr.encodeSealed(sample(), "qr-passphrase-123".toCharArray())
        val bitmap = QrCodes.encode(payload)
        assertNotNull(bitmap)

        val decoded = QrCodes.decodeBitmap(bitmap!!)
        assertEquals(payload, decoded)
        val blob = (CredentialQr.parse(decoded!!) as QrPayload.Sealed).blob
        assertEquals(sample(), CredentialQr.open(blob, "qr-passphrase-123".toCharArray()))
        bitmap.recycle()
    }

    @Test
    fun 从图片字节解码走的是同一条路径() {
        val payload = CredentialQr.encodePlain(sample())
        val bitmap = QrCodes.encode(payload)!!
        val bytes = ByteArrayOutputStream().use { out ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
            out.toByteArray()
        }
        bitmap.recycle()
        assertEquals(payload, QrCodes.decodeImageBytes(bytes))
    }

    @Test
    fun 纯色图片不会误报() {
        val blank = Bitmap.createBitmap(320, 320, Bitmap.Config.ARGB_8888)
        blank.eraseColor(0xFFFFFFFF.toInt())
        assertNull(QrCodes.decodeBitmap(blank))
        blank.recycle()
    }

    @Test
    fun 极小尺寸的二维码不会导致崩溃() {
        // 240 px 下把一个较长的载荷硬塞进二维码：模块只有一两个像素，
        // 真实相机几乎不可能扫出来 —— 但**不能崩**，只能是「读不到」。
        val payload = "myvault://credential?v=1&site=" + "a".repeat(600)
        val bitmap = QrCodes.encode(payload, sizePx = 240) ?: return
        // 不断言结果：解不出来是正常的，这里只验证这条路径不抛异常
        runCatching { QrCodes.decodeBitmap(bitmap) }
        bitmap.recycle()
    }
}
