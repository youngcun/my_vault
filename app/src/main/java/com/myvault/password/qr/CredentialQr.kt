package com.myvault.password.qr

import com.myvault.password.core.Base64Codec
import com.myvault.password.core.CryptoPrimitives
import com.myvault.password.core.Kdf

/**
 * 二维码承载的一条凭据。
 *
 * 刻意**不带** `id` / 时间戳 / 收藏标记：二维码是一个「交给别人」的载体，
 * 里面只该有对方真正需要的那五个字段。带上本机的数据库主键没有任何用处，
 * 却会把「这台设备上这条记录的内部标识」暴露出去。
 *
 * 字段与 [com.myvault.password.domain.VaultEntry] 同名，便于导入时逐字段搬过去；
 * 但两者是不同的类型 —— 领域模型会增加 id 与时间，且永远不该被直接塞进二维码。
 */
data class QrCredential(
    val site: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val notes: String = "",
) {
    /** 一条凭据至少要有站点或用户名，否则导入的是一条无法辨认的空记录。 */
    val isBlank: Boolean
        get() = site.isBlank() && username.isBlank() && password.isBlank() &&
            url.isBlank() && notes.isBlank()
}

/**
 * 二维码解析结果。
 *
 * 分成「能导入」与「认得出但不能导入」两类，是为了让界面能说清原因，
 * 而不是统一显示「无法识别的二维码」—— 后者会让用户以为是自己扫错了。
 */
sealed interface QrPayload {

    /** 明文凭据（`myvault://credential`）。 */
    data class Plain(val credential: QrCredential) : QrPayload

    /** 口令加密的凭据（`myvault://sealed`），需要用户输入口令才能解开。 */
    data class Sealed(val blob: SealedBlob) : QrPayload

    /** 格式合法、但本应用无法导入的二维码（给出具体原因）。 */
    data class Unsupported(val kind: UnsupportedKind) : QrPayload
}

/**
 * 「认得出但不能导入」的二维码种类。
 *
 * 这里的每一项都对应一个真实存在、用户很可能扫到的二维码格式。
 * 明确报出种类，比让用户以为「这个应用坏了」要好得多。
 */
enum class UnsupportedKind {
    /**
     * Windows Hello / iOS / Android 的「保存通行密钥」二维码。
     *
     * 它**不是**一条可导入的数据，而是一次**跨设备握手的入场券**：
     * 二维码里只有隧道地址、隧道 ID 与一次性密钥，手机扫到后要通过
     * BLE 或厂商的中转服务器与电脑建立加密通道，随后在通道里完成
     * WebAuthn 的密钥生成。私钥始终只存在于真正持有它的一方，
     * 从来不存在于二维码里。
     *
     * 因此它无法被「导入」：没有网络权限的应用既建立不了那条隧道，
     * 也没有任何可以导入的密码。这一点必须对用户讲明，而不是假装支持。
     */
    PASSKEY_HYBRID,

    /** `otpauth://` / `otpauth-migration://`：TOTP 动态口令，本应用暂不支持。 */
    TOTP,

    /** `WIFI:`：Wi-Fi 配置二维码（含 SSID 与 WPA 口令），不是登录凭据。 */
    WIFI,

    /** 其他无法识别的二维码文本。 */
    OTHER,
}

/** 二维码内容的**结构化**错误原因（文案由界面按当前语言渲染）。 */
enum class QrError {
    EMPTY,
    TOO_LONG,
    NOT_MYVAULT,
    BAD_FORMAT,
    BAD_VERSION,
    BAD_FIELD,
    BAD_BASE64,
    BAD_PARAMS,
    BAD_CIPHERTEXT,
    WRONG_PASSPHRASE,
    TOO_BIG_TO_ENCODE,
    EMPTY_CREDENTIAL,
}

/** 解析 / 生成二维码内容时抛出的异常，携带机器可判定的 [error]。 */
class QrFormatException(
    val error: QrError,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * MyVault 凭据二维码的编解码。
 *
 * 为什么需要自己定一个格式
 * ------------------------
 * 凭据二维码**没有**通用标准：Google Authenticator 的 `otpauth` 是动态口令、
 * Wi-Fi 二维码是网络配置、Windows 的 `FIDO:` 是通行密钥握手（见
 * [UnsupportedKind.PASSKEY_HYBRID]）。各密码管理器之间也没有相互认可的格式，
 * 所以这里显式定义一种，并把判定规则写在文档里（`docs/QR-IMPORT.md`），
 * 任何第三方工具都可以照着生成。
 *
 * 两种载荷
 * --------
 * 1. **明文** `myvault://credential?v=1&site=…&username=…&password=…`
 *
 *    字段用百分号编码，因此扫描器自带的「显示原文」看到的是可读文本，
 *    而不是一串 Base64。适合当面把一条密码递给另一台设备。
 *
 * 2. **口令加密** `myvault://sealed?v=1&kdf=argon2id&m=…&t=…&p=…&salt=…&data=…`
 *
 *    二维码是一个**广播介质**：屏幕上显示出来的内容，房间里任何一台设备
 *    都能拍到，截图也可能留在相册里。明文模式因此只适合一次性传递；
 *    需要长期留存（打印、贴在保险柜、放进工单）时应当用加密模式 ——
 *    这样即使二维码被别人拿到，没有口令也解不出密码。
 *
 *    加密使用的原语与备份文件完全一致（Argon2id → AES-256-GCM），
 *    **KDF 参数随载荷一起走**，因此十年后默认参数提高了，旧二维码依然能解开。
 *
 * 安全性上的几个刻意选择
 * ----------------------
 * - 载荷有字节上限（[MAX_PAYLOAD_BYTES]）：二维码最多也就装下 2 KB 左右，
 *   提前拒绝可以避免把「解码时才发现放不下」变成一个难懂的错误。
 * - 字段白名单：解析时只认 [FIELD_SITE] 等五个键，其余一律忽略。
 *   二维码是**不可信输入**，不能让一个陌生二维码往数据库里塞任意结构化数据。
 * - 不信任载荷里的任何长度/版本声明：版本过高直接拒绝（与备份文件的策略一致），
 *   未知版本的语义无法预判，宁可拒绝也不猜测。
 */
object CredentialQr {

    /** URL scheme。全小写，解析时忽略大小写。 */
    const val SCHEME = "myvault"

    /** 明文凭据的 host 部分。 */
    const val HOST_CREDENTIAL = "credential"

    /** 口令加密凭据的 host 部分。 */
    const val HOST_SEALED = "sealed"

    /** 当前格式版本。**只增不改**：解码端必须能继续读旧版本。 */
    const val FORMAT_VERSION = 1

    /**
     * 载荷（UTF-8）字节上限。
     *
     * 依据：QR 码在 M 级纠错、版本 40 时容量约 2331 字节。取 2000 留出余量，
     * 同时保证生成的二维码在 1024 px 下仍然可扫。超过这个长度多半是把
     * 一大段备注塞进来了 —— 那本就该走加密备份，而不是二维码。
     */
    const val MAX_PAYLOAD_BYTES = 2000

    /** 单字段长度上限（字符数），防止一个二维码把界面撑爆。 */
    const val MAX_FIELD_CHARS = 1024

    /** 备注可能略长，单独给一个上限。 */
    const val MAX_NOTES_CHARS = 2048

    private const val FIELD_SITE = "site"
    private const val FIELD_USERNAME = "username"
    private const val FIELD_PASSWORD = "password"
    private const val FIELD_URL = "url"
    private const val FIELD_NOTES = "notes"

    private const val KEY_VERSION = "v"
    private const val KEY_KDF = "kdf"
    private const val KEY_MEMORY = "m"
    private const val KEY_ITERATIONS = "t"
    private const val KEY_PARALLELISM = "p"
    private const val KEY_SALT = "salt"
    private const val KEY_DATA = "data"

    private const val KDF_ARGON2ID = "argon2id"

    /**
     * 用途隔离标签：二维码加密子密钥不得与备份、字段加密的密钥混用。
     * 同一把派生密钥被两处使用，会让任意一处的实现缺陷扩散到另一处。
     */
    private const val LABEL_ENC = "myvault/qr/v1/encryption"

    /** AAD 前缀：把「这段密文属于二维码格式 v1」绑进认证，防止跨格式搬运。 */
    private const val AAD_PREFIX = "myvault-qr-aad|"

    // ------------------------------------------------------------ 生成

    /**
     * 生成明文二维码内容。
     *
     * 调用方必须先向用户显示警告：这段文本**包含明文密码**，
     * 任何能拍到屏幕的设备都能读到它。
     */
    fun encodePlain(credential: QrCredential): String {
        val fields = encodeFields(credential)
        val payload = "$SCHEME://$HOST_CREDENTIAL?$KEY_VERSION=$FORMAT_VERSION&$fields"
        checkSize(payload)
        return payload
    }

    /**
     * 生成口令加密的二维码内容。
     *
     * @param passphrase 加密口令（调用方负责清零）。可以是空数组 —— 与备份口令
     *   的策略一致，允许用户选择「方便」而不是「更强」，但界面必须提示代价。
     */
    fun encodeSealed(credential: QrCredential, passphrase: CharArray): String {
        val fields = encodeFields(credential).toByteArray(Charsets.UTF_8)
        val salt = Kdf.newSalt()
        val params = Kdf.Argon2Params()
        val kek = Kdf.deriveArgon2id(passphrase, salt, params)
        try {
            val encKey = CryptoPrimitives.deriveSubKey(kek, LABEL_ENC)
            try {
                val header = sealedHeader(params, salt)
                val ciphertext = CryptoPrimitives.aesGcmEncrypt(
                    encKey,
                    fields,
                    (AAD_PREFIX + header).toByteArray(Charsets.UTF_8),
                )
                val payload = "$SCHEME://$HOST_SEALED?$header&$KEY_DATA=${Base64Codec.encodeUrl(ciphertext)}"
                checkSize(payload)
                return payload
            } finally {
                CryptoPrimitives.destroy(encKey)
            }
        } finally {
            CryptoPrimitives.destroy(kek)
            CryptoPrimitives.destroy(fields)
        }
    }

    // ------------------------------------------------------------ 解析

    /**
     * 解析扫描到的二维码文本。
     *
     * @throws QrFormatException 内容是本应用格式但结构损坏（[QrError.BAD_FORMAT] 等）
     */
    fun parse(raw: String): QrPayload {
        val text = raw.trim()
        if (text.isEmpty()) throw QrFormatException(QrError.EMPTY, "二维码内容为空")
        if (text.toByteArray(Charsets.UTF_8).size > MAX_PAYLOAD_BYTES) {
            throw QrFormatException(QrError.TOO_LONG, "二维码内容超过 $MAX_PAYLOAD_BYTES 字节")
        }

        // 先判定「认得出但不能导入」的种类，再尝试按本应用格式解析。
        // 顺序很重要：`FIDO:` 之类根本不含 `myvault:` 前缀，若先按本应用格式
        // 解析只会得到一个笼统的「格式错误」，用户就看不到真正的原因。
        if (!text.startsWith("$SCHEME:", ignoreCase = true)) {
            return QrPayload.Unsupported(classifyForeign(text))
        }

        val rest = text.substring(SCHEME.length + 1)
        if (!rest.startsWith("//")) {
            throw QrFormatException(QrError.BAD_FORMAT, "缺少 //")
        }
        val afterAuthority = rest.substring(2)
        val queryStart = afterAuthority.indexOf('?')
        if (queryStart < 0) throw QrFormatException(QrError.BAD_FORMAT, "缺少查询参数")
        val host = afterAuthority.substring(0, queryStart).trimEnd('/').lowercase()
        if (host.contains('/')) throw QrFormatException(QrError.BAD_FORMAT, "host 不合法")
        val query = parseQuery(afterAuthority.substring(queryStart + 1))

        return when (host) {
            HOST_CREDENTIAL -> parsePlain(query)
            HOST_SEALED -> parseSealed(query)
            else -> throw QrFormatException(QrError.BAD_FORMAT, "未知的二维码类型：$host")
        }
    }

    /**
     * 解开加密二维码。
     *
     * @throws QrFormatException [QrError.WRONG_PASSPHRASE] 表示口令错误**或**内容被篡改 ——
     *   两者在密码学上不可区分（GCM 认证失败就是失败），界面必须把两种可能都告诉用户。
     */
    fun open(blob: SealedBlob, passphrase: CharArray): QrCredential {
        val kek = Kdf.deriveArgon2id(passphrase, blob.salt, blob.params)
        try {
            val encKey = CryptoPrimitives.deriveSubKey(kek, LABEL_ENC)
            try {
                val plaintext = try {
                    CryptoPrimitives.aesGcmDecrypt(
                        encKey,
                        blob.ciphertext,
                        (AAD_PREFIX + blob.header()).toByteArray(Charsets.UTF_8),
                    )
                } catch (e: Exception) {
                    throw QrFormatException(
                        QrError.WRONG_PASSPHRASE,
                        "口令错误，或二维码内容已被篡改",
                        e,
                    )
                }
                try {
                    return decodeFields(String(plaintext, Charsets.UTF_8))
                } finally {
                    CryptoPrimitives.destroy(plaintext)
                }
            } finally {
                CryptoPrimitives.destroy(encKey)
            }
        } finally {
            CryptoPrimitives.destroy(kek)
        }
    }

    // ------------------------------------------------------------ 内部：明文载荷

    private fun parsePlain(query: Map<String, String>): QrPayload {
        requireVersion(query)
        val credential = credentialFrom(query)
        // 密码为空**不是**格式错误（用户可能只传站点与用户名），
        // 因此这里只拒绝「五个字段全空」——那说明扫码扫到了一个空壳。
        if (credential.isBlank) {
            throw QrFormatException(QrError.EMPTY_CREDENTIAL, "二维码里没有任何凭据字段")
        }
        return QrPayload.Plain(credential)
    }

    private fun parseSealed(query: Map<String, String>): QrPayload {
        requireVersion(query)
        val kdf = query[KEY_KDF] ?: throw QrFormatException(QrError.BAD_FORMAT, "缺少 kdf")
        if (kdf.lowercase() != KDF_ARGON2ID) {
            throw QrFormatException(QrError.BAD_PARAMS, "不支持的 KDF：$kdf")
        }
        val params = try {
            Kdf.Argon2Params(
                memoryKib = intParam(query, KEY_MEMORY, Kdf.Argon2Params.DEFAULT_MEMORY_KIB),
                iterations = intParam(query, KEY_ITERATIONS, Kdf.Argon2Params.DEFAULT_ITERATIONS),
                parallelism = intParam(query, KEY_PARALLELISM, Kdf.Argon2Params.DEFAULT_PARALLELISM),
            )
        } catch (e: IllegalArgumentException) {
            // Argon2Params 的 init 会校验 (m,t,p) 的范围。一个恶意二维码把
            // m 写成 512 MiB 就足以让设备 OOM —— 必须在这里变成可读错误。
            throw QrFormatException(QrError.BAD_PARAMS, "KDF 参数越界", e)
        }
        val salt = decodeBase64(query[KEY_SALT] ?: throw QrFormatException(QrError.BAD_FORMAT, "缺少 salt"))
        if (salt.size != Kdf.SALT_BYTES) {
            throw QrFormatException(QrError.BAD_PARAMS, "salt 长度不合法")
        }
        val ciphertext = decodeBase64(
            query[KEY_DATA] ?: throw QrFormatException(QrError.BAD_FORMAT, "缺少 data"),
        )
        if (ciphertext.size < CryptoPrimitives.MIN_CIPHERTEXT_BYTES) {
            throw QrFormatException(QrError.BAD_CIPHERTEXT, "密文长度不合法")
        }
        return QrPayload.Sealed(SealedBlob(params, salt, ciphertext))
    }

    private fun requireVersion(query: Map<String, String>) {
        val raw = query[KEY_VERSION] ?: throw QrFormatException(QrError.BAD_FORMAT, "缺少 v")
        val version = raw.toIntOrNull()
            ?: throw QrFormatException(QrError.BAD_VERSION, "版本号不是整数：$raw")
        if (version > FORMAT_VERSION) {
            // 与备份文件同一策略：未来版本的结构无法预判，宁可拒绝也不猜
            throw QrFormatException(QrError.BAD_VERSION, "二维码版本 $version 高于支持的 $FORMAT_VERSION")
        }
        if (version < 1) throw QrFormatException(QrError.BAD_VERSION, "版本号必须 ≥ 1")
    }

    private fun credentialFrom(query: Map<String, String>): QrCredential = QrCredential(
        site = field(query, FIELD_SITE),
        username = field(query, FIELD_USERNAME),
        password = field(query, FIELD_PASSWORD),
        url = field(query, FIELD_URL),
        notes = field(query, FIELD_NOTES, MAX_NOTES_CHARS),
    )

    private fun field(
        query: Map<String, String>,
        key: String,
        maxChars: Int = MAX_FIELD_CHARS,
    ): String {
        val value = query[key].orEmpty()
        if (value.length > maxChars) {
            throw QrFormatException(QrError.BAD_FIELD, "字段 $key 超过 $maxChars 字符")
        }
        return value
    }

    /**
     * 读取整数参数。
     *
     * 缺省时取默认值（兼容手写的简短载荷），**但写错了必须报错**：
     * 静默回退到默认值会让「m=abc」这种被改过的载荷看起来像正常载荷，
     * 最后只表现为一句含糊的「口令错误」。
     */
    private fun intParam(query: Map<String, String>, key: String, default: Int): Int {
        val raw = query[key] ?: return default
        return raw.toIntOrNull()
            ?: throw QrFormatException(QrError.BAD_PARAMS, "参数 $key 不是整数：$raw")
    }

    /** 把五个字段拼成查询串（与解析端共用同一套键名）。 */
    private fun encodeFields(credential: QrCredential): String {
        val parts = ArrayList<String>(5)
        appendField(parts, FIELD_SITE, credential.site, MAX_FIELD_CHARS)
        appendField(parts, FIELD_USERNAME, credential.username, MAX_FIELD_CHARS)
        appendField(parts, FIELD_PASSWORD, credential.password, MAX_FIELD_CHARS)
        appendField(parts, FIELD_URL, credential.url, MAX_FIELD_CHARS)
        appendField(parts, FIELD_NOTES, credential.notes, MAX_NOTES_CHARS)
        return parts.joinToString("&")
    }

    private fun decodeFields(text: String): QrCredential = credentialFrom(parseQuery(text))

    private fun appendField(parts: MutableList<String>, key: String, value: String, maxChars: Int) {
        if (value.isEmpty()) return          // 空字段不写，二维码越小越好扫
        if (value.length > maxChars) {
            throw QrFormatException(QrError.BAD_FIELD, "字段 $key 超过 $maxChars 字符")
        }
        parts += "$key=${percentEncode(value)}"
    }

    // ------------------------------------------------------------ 内部：查询串

    /**
     * 解析 `a=1&b=2` 形式的查询串。
     *
     * 不直接使用 `java.net.URI`：它对非法百分号编码、重复的 `?`、空段等
     * 各种边角的处理在不同 JDK/Android 版本上并不一致，而这里需要的行为很窄 ——
     * 自己写 30 行反而更可预测，也更容易被单元测试固定住。
     */
    private fun parseQuery(query: String): Map<String, String> {
        if (query.isEmpty()) return emptyMap()
        val result = LinkedHashMap<String, String>()
        for (pair in query.split('&')) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            if (eq <= 0) throw QrFormatException(QrError.BAD_FORMAT, "查询参数缺少 =")
            val key = pair.substring(0, eq)
            val value = percentDecode(pair.substring(eq + 1))
            // 重复键取第一个：后面的可以被构造成「覆盖掉前面的值」，
            // 而这种歧义没有任何正当用途。
            result.putIfAbsent(key, value)
        }
        return result
    }

    /**
     * 扫描到的内容不属于本应用格式时，尽力判断它是什么。
     *
     * 判定**只依据公开的 scheme**，不做内容嗅探：把「看起来像密码的文本」
     * 猜成凭据，等于让一个陌生二维码决定往库里写什么。
     */
    private fun classifyForeign(text: String): UnsupportedKind {
        val lower = text.lowercase()
        return when {
            lower.startsWith("fido:") -> UnsupportedKind.PASSKEY_HYBRID
            lower.startsWith("otpauth:") || lower.startsWith("otpauth-migration:") ->
                UnsupportedKind.TOTP
            lower.startsWith("wifi:") -> UnsupportedKind.WIFI
            else -> UnsupportedKind.OTHER
        }
    }

    // ------------------------------------------------------------ 内部：编码工具

    private fun sealedHeader(params: Kdf.Argon2Params, salt: ByteArray): String =
        "$KEY_VERSION=$FORMAT_VERSION&$KEY_KDF=$KDF_ARGON2ID" +
            "&$KEY_MEMORY=${params.memoryKib}" +
            "&$KEY_ITERATIONS=${params.iterations}" +
            "&$KEY_PARALLELISM=${params.parallelism}" +
            "&$KEY_SALT=${Base64Codec.encodeUrl(salt)}"

    private fun checkSize(payload: String) {
        if (payload.toByteArray(Charsets.UTF_8).size > MAX_PAYLOAD_BYTES) {
            throw QrFormatException(
                QrError.TOO_BIG_TO_ENCODE,
                "内容超过 $MAX_PAYLOAD_BYTES 字节，放不进二维码",
            )
        }
    }

    private fun decodeBase64(text: String): ByteArray = try {
        Base64Codec.decodeUrl(text)
    } catch (e: IllegalArgumentException) {
        throw QrFormatException(QrError.BAD_BASE64, "不是合法的 Base64URL", e)
    }

    private fun isUnreserved(b: Int): Boolean =
        (b in 'A'.code..'Z'.code) || (b in 'a'.code..'z'.code) ||
            (b in '0'.code..'9'.code) ||
            b == '-'.code || b == '.'.code || b == '_'.code || b == '~'.code

    /**
     * 百分号编码（RFC 3986 的非保留字符集）。
     *
     * **不用** `URLEncoder`：那是 HTML 表单编码，会把空格写成 `+`，
     * 而 `+` 在二维码里是合法字面量 —— 一个包含 `+` 的密码经它编码再解码
     * 就会变成空格。这类缺陷只会在特定密码上出现，极难排查。
     */
    private fun percentEncode(value: String): String {
        val bytes = value.toByteArray(Charsets.UTF_8)
        val sb = StringBuilder(bytes.size + 16)
        for (raw in bytes) {
            val b = raw.toInt() and 0xFF
            if (isUnreserved(b)) {
                sb.append(b.toChar())
            } else {
                sb.append('%')
                sb.append(HEX[b ushr 4])
                sb.append(HEX[b and 0x0F])
            }
        }
        return sb.toString()
    }

    private fun percentDecode(text: String): String {
        val out = java.io.ByteArrayOutputStream(text.length)
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (c == '%') {
                if (i + 2 >= text.length) throw QrFormatException(QrError.BAD_FORMAT, "百分号编码不完整")
                val hi = hexValue(text[i + 1])
                val lo = hexValue(text[i + 2])
                if (hi < 0 || lo < 0) throw QrFormatException(QrError.BAD_FORMAT, "百分号编码不是十六进制")
                out.write((hi shl 4) or lo)
                i += 3
            } else {
                // 字面字符按 UTF-8 重新编码，保证与上面的字节流是同一种表示
                val end = i + Character.charCount(text.codePointAt(i))
                out.write(text.substring(i, end).toByteArray(Charsets.UTF_8))
                i = end
            }
        }
        // 严格按 UTF-8 解码：默认的 String(bytes, UTF_8) 会把非法字节序列
        // 悄悄换成 U+FFFD，于是一段损坏的载荷会变成一个「看起来正常但有怪字符」
        // 的密码被存进库里。宁可在这里失败。
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(out.toByteArray()))
                .toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw QrFormatException(QrError.BAD_FORMAT, "百分号编码不是合法的 UTF-8", e)
        }
    }

    private fun hexValue(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    private val HEX = "0123456789ABCDEF".toCharArray()
}

/**
 * 口令加密载荷的密文部分。
 *
 * 单独成类型（而不是在解析时立刻解密）的原因很实际：解密需要用户输入口令，
 * 那是一次可能失败的交互。把「结构解析」与「解开密文」分开，
 * 界面才能先显示「这是一个加密二维码，请输入口令」，而不是卡在一个没有反馈的等待里。
 */
data class SealedBlob(
    val params: Kdf.Argon2Params,
    val salt: ByteArray,
    val ciphertext: ByteArray,
) {
    /** 参与 AAD 的头部（不含密文本身）。参数被改动时解密必然失败。 */
    fun header(): String = "v=${CredentialQr.FORMAT_VERSION}&kdf=argon2id" +
        "&m=${params.memoryKib}&t=${params.iterations}&p=${params.parallelism}" +
        "&salt=${Base64Codec.encodeUrl(salt)}"

    // 数组字段的 equals/hashCode 必须自己实现，否则 data class 生成的是引用比较，
    // 单元测试里「解析出的 blob 与原始 blob 相同」会莫名其妙地失败。
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SealedBlob) return false
        return params == other.params &&
            salt.contentEquals(other.salt) &&
            ciphertext.contentEquals(other.ciphertext)
    }

    override fun hashCode(): Int {
        var result = params.hashCode()
        result = 31 * result + salt.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        return result
    }
}
