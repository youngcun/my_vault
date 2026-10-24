package com.myvault.password.qr

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.content.Context
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 二维码的图像层：文本 ↔ 位图，以及相机逐帧识别。
 *
 * 这一层只做「像素 ↔ 文本」，**不解释文本内容** —— 解析与校验在
 * [CredentialQr]（纯 JVM、可单测）。分开的理由很实际：识别算法依赖 Android
 * 的位图与相机，而「这段文本是不是一条凭据」必须能在没有设备的测试里覆盖。
 */
object QrCodes {

    /**
     * 静区宽度（模块数）。QR 规范要求 4；少于这个宽度，相当一部分扫码器
     * 会直接定位失败。实测静区 2 模块时 ZXing 自己就解不出来。
     */
    const val QUIET_ZONE_MODULES = 4

    /** 生成二维码的边长（像素）。640 足够 4K 屏与普通相机近距扫描。 */
    const val DEFAULT_SIZE_PX = 640

    /** 解码提示。TRY_HARDER 让 ZXing 扫描更多行，代价是每帧更慢。 */
    private fun decodeHints(pureBarcode: Boolean = false): Map<DecodeHintType, Any> {
        val hints = HashMap<DecodeHintType, Any>(4)
        hints[DecodeHintType.POSSIBLE_FORMATS] = listOf(BarcodeFormat.QR_CODE)
        hints[DecodeHintType.CHARACTER_SET] = "UTF-8"
        hints[DecodeHintType.TRY_HARDER] = true
        if (pureBarcode) hints[DecodeHintType.PURE_BARCODE] = true
        return hints
    }

    // ------------------------------------------------------------ 生成

    /**
     * 把文本编码成二维码位图。
     *
     * @return 位图；内容放不进二维码时返回 null（调用方已经用
     *   [CredentialQr.encodePlain] / [CredentialQr.encodeSealed] 校验过长度，
     *   走到这里为 null 说明是极端情况）。
     */
    fun encode(text: String, sizePx: Int = DEFAULT_SIZE_PX): Bitmap? = try {
        val matrix = QRCodeWriter().encode(
            text,
            BarcodeFormat.QR_CODE,
            sizePx,
            sizePx,
            mapOf(
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
                EncodeHintType.CHARACTER_SET to "UTF-8",
                EncodeHintType.MARGIN to QUIET_ZONE_MODULES,
            ),
        )
        val width = matrix.width
        val height = matrix.height
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            val offset = y * width
            for (x in 0 until width) {
                pixels[offset + x] = if (matrix.get(x, y)) BLACK else WHITE
            }
        }
        Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).apply {
            setPixels(pixels, 0, width, 0, 0, width, height)
        }
    } catch (e: Exception) {
        null
    }

    // ------------------------------------------------------------ 从图片解码

    /**
     * 从用户选中的图片文件解码。
     *
     * 会先按尺寸做降采样：一张 1200 万像素的照片直接转成 ARGB 数组要 48 MB，
     * 在低端机上足以 OOM，而二维码根本不需要那个分辨率。
     */
    fun decodeImage(context: Context, uri: Uri): String? {
        val bytes = runCatching {
            context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        }.getOrNull() ?: return null
        return decodeImageBytes(bytes)
    }

    /** 便于单元/仪器测试直接喂字节。 */
    fun decodeImageBytes(bytes: ByteArray): String? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null

        val options = BitmapFactory.Options().apply {
            inSampleSize = sampleSizeFor(bounds.outWidth, bounds.outHeight, MAX_DECODE_EDGE_PX)
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options) ?: return null
        return try {
            decodeBitmap(bitmap)
        } finally {
            bitmap.recycle()
        }
    }

    /** 计算 2 的幂次降采样倍率，使长边不超过 [maxEdge]。 */
    internal fun sampleSizeFor(width: Int, height: Int, maxEdge: Int): Int {
        var sample = 1
        var longest = maxOf(width, height)
        while (longest / 2 >= maxEdge) {
            sample *= 2
            longest /= 2
        }
        return sample
    }

    /**
     * 从位图解码。
     *
     * 三级回退是**必要**的，不是防御性编程：
     *  1. 普通定位 —— 照片/截图的主流情况；
     *  2. `PURE_BARCODE` —— 整张图就是二维码（例如用户截的图），
     *     此时跳过定位直接按已知边界采样，成功率更高；
     *  3. 旋转 90°/180°/270° —— 相机与相册对 EXIF 方向的处理并不一致，
     *     而二维码没有方向信息可以用来纠正。
     */
    fun decodeBitmap(bitmap: Bitmap): String? {
        if (bitmap.width <= 0 || bitmap.height <= 0) return null
        var width = bitmap.width
        var height = bitmap.height
        var pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)

        // 旋转是**自己转像素**，而不是调用 LuminanceSource.rotateCounterClockwise()：
        // RGBLuminanceSource 没有实现那个方法，调用会直接抛 UnsupportedOperationException
        // （这是设备端测试抓到的真实缺陷，纯 JVM 测试里因为没有位图而覆盖不到）。
        repeat(4) { attempt ->
            val source = RGBLuminanceSource(width, height, pixels)
            decodeLuminance(source, pureBarcode = false)?.let { return it }
            decodeLuminance(source, pureBarcode = true)?.let { return it }
            if (attempt < 3) {
                val rotated = rotateClockwise(pixels, width, height)
                pixels = rotated.first
                width = rotated.second
                height = rotated.third
            }
        }
        return null
    }

    /**
     * 把 ARGB 像素顺时针旋转 90°。
     *
     * @return (像素, 新宽度, 新高度)
     */
    private fun rotateClockwise(pixels: IntArray, width: Int, height: Int): Triple<IntArray, Int, Int> {
        val out = IntArray(pixels.size)
        val newWidth = height
        for (y in 0 until height) {
            val rowOffset = y * width
            for (x in 0 until width) {
                // 源 (x, y) → 目标 (newWidth - 1 - y, x)
                out[x * newWidth + (newWidth - 1 - y)] = pixels[rowOffset + x]
            }
        }
        return Triple(out, newWidth, width)
    }

    private fun decodeLuminance(source: com.google.zxing.LuminanceSource, pureBarcode: Boolean): String? =
        try {
            val reader = MultiFormatReader()
            val bitmap = BinaryBitmap(HybridBinarizer(source))
            reader.decode(bitmap, decodeHints(pureBarcode)).text
        } catch (e: Exception) {
            // NotFound / Format / Checksum 都只意味着「这张图里没有可读的二维码」，
            // 不是异常情况 —— 相机每秒要跑十几次，不能每次都打日志。
            null
        }

    // ------------------------------------------------------------ 相机逐帧识别

    /**
     * CameraX 的逐帧分析器。
     *
     * 设计要点：
     *  - **单线程**：ZXing 的 Reader 不是线程安全的，分析器由 CameraX 在
     *    我们给的 Executor 上串行调用；
     *  - **命中即暂停**：识别成功后立刻 [pause]，否则用户还没看清结果，
     *    界面就已经被同一张二维码重复触发了十几次；
     *  - **每帧都 close**：ImageProxy 不关会导致相机停止出新帧（表现为「扫码界面卡住」）。
     */
    class CameraAnalyzer(
        private val onDecoded: (String) -> Unit,
    ) : ImageAnalysis.Analyzer {

        private val paused = AtomicBoolean(false)
        private val reader = MultiFormatReader().apply { setHints(decodeHints()) }

        fun pause() = paused.set(true)

        fun resume() = paused.set(false)

        override fun analyze(image: ImageProxy) {
            if (paused.get()) {
                image.close()
                return
            }
            try {
                val text = decodeImageProxy(image)
                if (text != null && paused.compareAndSet(false, true)) {
                    onDecoded(text)
                }
            } catch (e: Exception) {
                // 单帧失败不值得上报：下一帧会重试
            } finally {
                image.close()
            }
        }

        private fun decodeImageProxy(image: ImageProxy): String? {
            val plane = image.planes.firstOrNull() ?: return null
            val buffer = plane.buffer
            val data = ByteArray(buffer.remaining())
            buffer.get(data)

            // rowStride 可能大于图像宽度（相机为了对齐会补几列），
            // 因此 dataWidth 用 rowStride，裁剪区域仍是真实的 width/height。
            val rowStride = plane.rowStride
            if (rowStride < image.width) return null
            // 有些设备返回的 Y 平面末尾不足一整行（padding 被裁掉），
            // 用完整行数做上界，避免越界读取。
            val rows = minOf(image.height, if (rowStride > 0) data.size / rowStride else 0)
            if (rows <= 0) return null
            val source = PlanarYUVLuminanceSource(
                data,
                rowStride,
                rows,
                0,
                0,
                image.width,
                rows,
                false,
            )
            var rotated: com.google.zxing.LuminanceSource = source
            // 相机传感器方向与屏幕方向不一致：不转正的话，竖屏扫描时
            // 二维码在解码器眼里是躺倒的，识别率会明显下降。
            repeat((image.imageInfo.rotationDegrees / 90).coerceIn(0, 3)) {
                rotated = rotated.rotateCounterClockwise()
            }
            return try {
                reader.decodeWithState(BinaryBitmap(HybridBinarizer(rotated))).text
            } catch (e: Exception) {
                null
            } finally {
                reader.reset()
            }
        }
    }

    /** 相机分析用的单线程执行器（调用方负责在离开界面时 shutdown）。 */
    fun newAnalysisExecutor(): java.util.concurrent.ExecutorService =
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "myvault-qr-analyzer").apply { isDaemon = true }
        }

    /** 单张图片解码前的长边上限。 */
    private const val MAX_DECODE_EDGE_PX = 1600

    private const val BLACK = 0xFF000000.toInt()
    private const val WHITE = 0xFFFFFFFF.toInt()
}
