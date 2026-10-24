package com.myvault.password.qr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * 二维码凭据编解码测试。
 *
 * 重点覆盖四类风险：
 *  1. **可往返**：生成的载荷必须能被同一套解析逻辑原样读回（含中文、emoji、各种符号）；
 *  2. **可被真二维码承载**：载荷要过一遍 ZXing 的编码/解码，证明它不是「只在字符串里合法」；
 *  3. **机密性**：加密模式下的载荷里不能出现明文密码；
 *  4. **不可信输入**：损坏的 Base64、越界的 KDF 参数、超长字段、未来版本都必须被拒绝，
 *     且给出**可区分**的错误类型 —— 界面要靠它告诉用户到底是哪一种问题。
 */
class CredentialQrTest {

    private fun sample() = QrCredential(
        site = "示例站点·MyVault",
        username = "sziron@outlook.com",
        // 刻意塞满所有容易出错的字符：百分号、与号、等号、加号、空格、换行、emoji
        password = "a%b&c=d+e f%20g\n第二行🔐",
        url = "https://example.com/login?a=1&b=2",
        notes = "备注：含 '单引号' 与 \"双引号\"，以及 #井号",
    )

    private fun assertThrows(error: QrError, block: () -> Unit) {
        try {
            block()
            fail("应当抛出 $error")
        } catch (e: QrFormatException) {
            assertEquals("错误类型不符：${e.message}", error, e.error)
        }
    }

    // ------------------------------------------------------------ 明文往返

    @Test
    fun `明文载荷可完整往返`() {
        val original = sample()
        val payload = CredentialQr.encodePlain(original)
        val parsed = CredentialQr.parse(payload)
        assertTrue(parsed is QrPayload.Plain)
        assertEquals(original, (parsed as QrPayload.Plain).credential)
    }

    @Test
    fun `明文载荷是可直接阅读的文本而不是 Base64`() {
        val payload = CredentialQr.encodePlain(sample())
        // 扫描器自带的「显示原文」应当能看出这是什么，否则用户无法判断能否导入
        assertTrue(payload.startsWith("myvault://credential?"))
        assertTrue(payload.contains("site="))
        assertTrue(payload.contains("username="))
        // 空白与换行必须被编码，否则会破坏 QR 文本解析
        assertFalse(payload.contains(" "))
        assertFalse(payload.contains("\n"))
    }

    @Test
    fun `空字段不写进载荷`() {
        val payload = CredentialQr.encodePlain(
            QrCredential(site = "only-site", password = "p"),
        )
        val parsed = CredentialQr.parse(payload) as QrPayload.Plain
        assertEquals("", parsed.credential.username)
        assertEquals("", parsed.credential.url)
        assertFalse(payload.contains("username="))
        assertFalse(payload.contains("notes="))
    }

    @Test
    fun `加号不会被当成空格`() {
        // URLEncoder 会把空格写成 +，导致「含 + 的密码」解码后变成空格。
        // 这条用例把这个坑固定住。
        val credential = QrCredential(site = "s", password = "a+b c")
        val parsed = CredentialQr.parse(CredentialQr.encodePlain(credential)) as QrPayload.Plain
        assertEquals("a+b c", parsed.credential.password)
    }

    @Test
    fun `明文载荷不超过二维码容量`() {
        val payload = CredentialQr.encodePlain(sample())
        val bytes = payload.toByteArray(Charsets.UTF_8).size
        assertTrue("载荷 $bytes 字节过大", bytes <= CredentialQr.MAX_PAYLOAD_BYTES)
    }

    // ------------------------------------------------------------ 加密往返

    @Test
    fun `加密载荷可完整往返`() {
        val original = sample()
        val payload = CredentialQr.encodeSealed(original, "qr-passphrase-123".toCharArray())
        val parsed = CredentialQr.parse(payload)
        assertTrue(parsed is QrPayload.Sealed)
        val opened = CredentialQr.open((parsed as QrPayload.Sealed).blob, "qr-passphrase-123".toCharArray())
        assertEquals(original, opened)
    }

    @Test
    fun `加密载荷里不出现任何明文字段`() {
        val original = QrCredential(
            site = "DistinctiveSite-8842",
            username = "distinctive-user-8842@example.com",
            password = "Zq7-Distinctive-QrPassword-8842",
            url = "https://distinctive-host-8842.example.com/login",
            notes = "DistinctiveNotes-8842",
        )
        val payload = CredentialQr.encodeSealed(original, "qr-passphrase-123".toCharArray())
        listOf(
            original.site, original.username, original.password, original.url, original.notes,
        ).forEach { secret ->
            assertFalse("加密载荷泄露了明文：$secret", payload.contains(secret))
        }
        // 也不该出现百分号编码后的形态
        assertFalse(payload.contains("DistinctiveSite"))
        assertFalse(payload.contains("8842"))
    }

    @Test
    fun `同一凭据两次加密得到不同载荷`() {
        // 每次都用新的 salt 与 GCM nonce；相同说明随机源没生效
        val a = CredentialQr.encodeSealed(sample(), "pass-1".toCharArray())
        val b = CredentialQr.encodeSealed(sample(), "pass-1".toCharArray())
        assertNotEquals(a, b)
    }

    @Test
    fun `错误口令被拒绝`() {
        val payload = CredentialQr.encodeSealed(sample(), "right-pass".toCharArray())
        val blob = (CredentialQr.parse(payload) as QrPayload.Sealed).blob
        assertThrows(QrError.WRONG_PASSPHRASE) {
            CredentialQr.open(blob, "wrong-pass".toCharArray())
        }
    }

    @Test
    fun `篡改密文被拒绝`() {
        val payload = CredentialQr.encodeSealed(sample(), "right-pass".toCharArray())
        val blob = (CredentialQr.parse(payload) as QrPayload.Sealed).blob
        val tampered = blob.ciphertext.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()
        assertThrows(QrError.WRONG_PASSPHRASE) {
            CredentialQr.open(blob.copy(ciphertext = tampered), "right-pass".toCharArray())
        }
    }

    @Test
    fun `篡改 KDF 参数被拒绝`() {
        // 把迭代次数从默认值改小，是「降低爆破成本」这类攻击的第一步。
        // AAD 里绑定了 (m,t,p,salt)，所以改参数必然导致解密失败。
        val payload = CredentialQr.encodeSealed(sample(), "right-pass".toCharArray())
        val original = (CredentialQr.parse(payload) as QrPayload.Sealed).blob
        val downgraded = original.copy(params = original.params.copy(iterations = 1))
        assertThrows(QrError.WRONG_PASSPHRASE) {
            CredentialQr.open(downgraded, "right-pass".toCharArray())
        }
    }

    @Test
    fun `加密载荷的 KDF 参数随载荷一起走`() {
        val payload = CredentialQr.encodeSealed(sample(), "right-pass".toCharArray())
        val blob = (CredentialQr.parse(payload) as QrPayload.Sealed).blob
        assertEquals(com.myvault.password.core.Kdf.Argon2Params.DEFAULT_MEMORY_KIB, blob.params.memoryKib)
        assertEquals(com.myvault.password.core.Kdf.Argon2Params.DEFAULT_ITERATIONS, blob.params.iterations)
        assertEquals(com.myvault.password.core.Kdf.SALT_BYTES, blob.salt.size)
        assertTrue(payload.contains("kdf=argon2id"))
    }

    // ------------------------------------------------------------ 不可信输入

    @Test
    fun `空内容被拒绝`() {
        assertThrows(QrError.EMPTY) { CredentialQr.parse("   ") }
    }

    @Test
    fun `超长内容在解析前就被拒绝`() {
        val huge = "myvault://credential?v=1&site=" + "a".repeat(CredentialQr.MAX_PAYLOAD_BYTES)
        assertThrows(QrError.TOO_LONG) { CredentialQr.parse(huge) }
    }

    @Test
    fun `超长字段无法生成`() {
        val tooLong = QrCredential(site = "s", notes = "n".repeat(CredentialQr.MAX_NOTES_CHARS + 1))
        assertThrows(QrError.BAD_FIELD) { CredentialQr.encodePlain(tooLong) }
    }

    @Test
    fun `内容超长时明确报出放不进二维码`() {
        // 每个字段都合法（≤1024 字符），合起来却超过二维码容量
        val bulky = QrCredential(
            site = "s".repeat(1024),
            username = "u".repeat(1024),
            password = "p".repeat(1024),
        )
        assertThrows(QrError.TOO_BIG_TO_ENCODE) { CredentialQr.encodePlain(bulky) }
    }

    @Test
    fun `未来版本被拒绝`() {
        assertThrows(QrError.BAD_VERSION) {
            CredentialQr.parse("myvault://credential?v=99&site=x&password=y")
        }
    }

    @Test
    fun `版本号缺省或非法被拒绝`() {
        assertThrows(QrError.BAD_FORMAT) {
            CredentialQr.parse("myvault://credential?site=x")
        }
        assertThrows(QrError.BAD_VERSION) {
            CredentialQr.parse("myvault://credential?v=abc&site=x")
        }
    }

    @Test
    fun `没有字段的明文载荷被拒绝`() {
        assertThrows(QrError.EMPTY_CREDENTIAL) {
            CredentialQr.parse("myvault://credential?v=1")
        }
    }

    @Test
    fun `损坏的 Base64 被拒绝`() {
        val payload = CredentialQr.encodeSealed(sample(), "right-pass".toCharArray())
        val broken = payload.replace(Regex("data=[^&]+"), "data=***不是Base64***")
        assertThrows(QrError.BAD_BASE64) { CredentialQr.parse(broken) }
    }

    @Test
    fun `越界的 Argon2 参数被拒绝而不是把设备拖死`() {
        // m 是内存开销：一个陌生二维码写 512 MiB 就足以让低端机 OOM
        val payload = CredentialQr.encodeSealed(sample(), "right-pass".toCharArray())
        val broken = payload.replace(Regex("m=\\d+"), "m=999999")
        assertThrows(QrError.BAD_PARAMS) { CredentialQr.parse(broken) }
    }

    @Test
    fun `非整数的 KDF 参数被拒绝而不是静默取默认值`() {
        // 静默回退会让「被改过的载荷」看起来像正常载荷，最终只表现为
        // 一句含糊的「口令错误」—— 必须在这里就报出参数问题。
        val payload = CredentialQr.encodeSealed(sample(), "right-pass".toCharArray())
        val broken = payload.replace(Regex("t=\\d+"), "t=abc")
        assertThrows(QrError.BAD_PARAMS) { CredentialQr.parse(broken) }
    }

    @Test
    fun `百分号编码不完整被拒绝`() {
        assertThrows(QrError.BAD_FORMAT) {
            CredentialQr.parse("myvault://credential?v=1&site=%E4%BD")
        }
        assertThrows(QrError.BAD_FORMAT) {
            CredentialQr.parse("myvault://credential?v=1&site=%ZZ")
        }
    }

    @Test
    fun `缺少 scheme 分隔符被拒绝`() {
        assertThrows(QrError.BAD_FORMAT) { CredentialQr.parse("myvault:credential?v=1") }
    }

    // ------------------------------------------------------------ 「认得出但不能导入」

    @Test
    fun `通行密钥二维码被识别为跨设备握手而不是数据`() {
        // Windows 安全中心「保存通行密钥」的二维码就是这种格式：
        // 里面没有密码，只有隧道地址与一次性密钥。
        val windowsStyle = "FIDO:/1320000000000000000000000000000000000000000000000000000000"
        val parsed = CredentialQr.parse(windowsStyle)
        assertTrue(parsed is QrPayload.Unsupported)
        assertEquals(UnsupportedKind.PASSKEY_HYBRID, (parsed as QrPayload.Unsupported).kind)
    }

    @Test
    fun `动态口令二维码被识别`() {
        val parsed = CredentialQr.parse("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        assertEquals(UnsupportedKind.TOTP, (parsed as QrPayload.Unsupported).kind)
        val migration = CredentialQr.parse("otpauth-migration://offline?data=CjEKCkhlbGxv")
        assertEquals(UnsupportedKind.TOTP, (migration as QrPayload.Unsupported).kind)
    }

    @Test
    fun `Wi-Fi 二维码被识别`() {
        val parsed = CredentialQr.parse("WIFI:T:WPA;S:MyNetwork;P:secret;;")
        assertEquals(UnsupportedKind.WIFI, (parsed as QrPayload.Unsupported).kind)
    }

    @Test
    fun `普通文本二维码被归为无法识别`() {
        val parsed = CredentialQr.parse("https://example.com")
        assertEquals(UnsupportedKind.OTHER, (parsed as QrPayload.Unsupported).kind)
    }

    @Test
    fun `大小写不敏感地识别 scheme`() {
        val payload = CredentialQr.encodePlain(QrCredential(site = "s", password = "p"))
            .replace("myvault://credential", "MYVAULT://CREDENTIAL")
        val parsed = CredentialQr.parse(payload)
        assertTrue(parsed is QrPayload.Plain)
    }

    // ------------------------------------------------------------ 真二维码往返

    /**
     * 把载荷真的编成 QR 矩阵、再解码回来。
     *
     * 这条用例回答的是「字符串层面往返成功」之外的问题：
     * 载荷在**经过纠错编码、模块化、再解码**之后是否依然完整？
     * 一个只在字符串里能往返的格式，扫到手机上可能是另一回事。
     *
     * 为什么用 `PURE_BARCODE` 而不是走图像定位：这里给解码器的是一张
     * **没有任何光学失真**的合成图（模块边界是像素级精确的），而 ZXing 的
     * 定位器是基于多行扫描的启发式算法 —— 在真实照片上工作良好，
     * 在这种「过于干净」的图上反而会偶尔估算出错误的版本尺寸（实测约 1/6）。
     * 那是**测试夹具的问题，不是符号的问题**：同一张图的功能图形、格式信息、
     * 数据与纠错码都完全正确，`PURE_BARCODE` 一定能读出来。
     * 因此这里只验证「载荷 ↔ 符号」这一层；图像定位的健壮性由 App 侧的多级回退
     * （普通定位 → 纯码 → 旋转）来保证，而不是靠这条用例。
     */
    @Test
    fun `明文载荷经真二维码编码解码后仍可导入`() {
        assertSurvivesQrRoundTrip(CredentialQr.encodePlain(sample()))
    }

    @Test
    fun `加密载荷经真二维码编码解码后仍可解开`() {
        val payload = CredentialQr.encodeSealed(sample(), "pass-1234".toCharArray())
        val decoded = assertSurvivesQrRoundTrip(payload)
        val blob = (CredentialQr.parse(decoded) as QrPayload.Sealed).blob
        assertEquals(sample(), CredentialQr.open(blob, "pass-1234".toCharArray()))
    }

    /** 编码 → 解码；返回解出的文本，并断言与原文本一致。 */
    private fun assertSurvivesQrRoundTrip(payload: String): String {
        val matrix = qrMatrix(payload)
        // 每模块放大 4 倍再交给解码器：1:1 的位图在二值化阶段过于脆弱，
        // 放大后更接近「手机拍到的样子」，也让这条用例真正在测纠错与采样。
        val scale = 4
        val width = matrix.width * scale
        val height = matrix.height * scale
        val pixels = IntArray(width * height) { index ->
            val x = index % width
            val y = index / width
            if (matrix.get(x / scale, y / scale)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
        }
        val source = com.google.zxing.RGBLuminanceSource(width, height, pixels)
        val bitmap = com.google.zxing.BinaryBitmap(com.google.zxing.common.HybridBinarizer(source))
        // 静区必须是 4 模块：少于这个宽度，真实扫码器会直接定位失败
        assertEquals(4, matrix.getTopLeftOnBit()?.get(1))
        val result = com.google.zxing.MultiFormatReader().decode(
            bitmap,
            mapOf(
                com.google.zxing.DecodeHintType.POSSIBLE_FORMATS to listOf(com.google.zxing.BarcodeFormat.QR_CODE),
                com.google.zxing.DecodeHintType.CHARACTER_SET to "UTF-8",
                com.google.zxing.DecodeHintType.PURE_BARCODE to true,
            ),
        )
        assertEquals(payload, result.text)
        return result.text
    }

    private fun qrMatrix(payload: String): com.google.zxing.common.BitMatrix {
        val hints = mapOf(
            com.google.zxing.EncodeHintType.ERROR_CORRECTION to
                com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M,
            com.google.zxing.EncodeHintType.CHARACTER_SET to "UTF-8",
            // 与 App 侧生成二维码时一致：QR 规范要求 4 模块静区，少了会在扫码时
            // 定位失败（这是实测过的：静区 2 模块时部分解码器直接报「找不到」）。
            com.google.zxing.EncodeHintType.MARGIN to 4,
        )
        return com.google.zxing.qrcode.QRCodeWriter().encode(
            payload,
            com.google.zxing.BarcodeFormat.QR_CODE,
            0,
            0,
            hints,
        )
    }
}
