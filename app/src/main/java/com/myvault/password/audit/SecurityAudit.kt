package com.myvault.password.audit

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.myvault.password.R
import java.security.MessageDigest

/**
 * 运行时安全自证。
 *
 * 这个类的存在本身就是本项目的核心主张：**安全应当可被用户独立验证，
 * 而不是靠一句「我们很安全」**。它从正在运行的进程和它自己的 APK 里
 * 读取事实，不做任何网络请求。
 *
 * 能被独立验证的事实
 * ----------------
 *  1. 本应用是否声明了 INTERNET 权限 —— 没有它，Linux 内核会拒绝
 *     任何 socket 创建（`socket()` 返回 EPERM），这不是「我们承诺不联网」，
 *     而是「系统不允许联网」；
 *  2. 实际声明的全部权限清单；
 *  3. APK 文件的 SHA-256 —— 用户可以拿它和官方发布值对照，
 *     确认安装的二进制没有被替换；
 *  4. 签名证书的 SHA-256 —— 确认 APK 由同一把私钥签名，
 *     这是「没有被二次打包」的密码学证据；
 *  5. 是否 debuggable —— debug 构建可被 `run-as` / JDWP 附加，不应长期使用。
 */
class SecurityAudit(private val context: Context) {

    data class Report(
        val packageName: String,
        val versionName: String,
        val versionCode: Long,
        val hasInternetPermission: Boolean,
        /** 是否存在任何形式的网络相关权限。 */
        val networkPermissions: List<String>,
        val declaredPermissions: List<String>,
        val apkSha256: String?,
        val signerSha256: String?,
        val isDebuggable: Boolean,
        val backupAllowed: Boolean,
        val biometricHardwarePresent: Boolean,
        val sdkInt: Int,
    ) {
        /** 最重要的判定：是否零网络权限。 */
        val networkClean: Boolean get() = networkPermissions.isEmpty()
    }

    /**
     * 所有被视为「网络能力」的权限。
     *
     * 注意 `ACCESS_NETWORK_STATE` 与 `ACCESS_WIFI_STATE` 本身不提供收发数据的能力，
     * 但它们能泄露「设备在什么网络里」。一个真正离线优先的密码库没有任何
     * 正当理由申请它们，因此一并纳入检查。
     */
    private val networkPermissionNames = setOf(
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.CHANGE_WIFI_MULTICAST_STATE",
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.NFC",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
    )

    fun collect(): Report {
        val pm = context.packageManager
        val packageName = context.packageName

        val info: android.content.pm.PackageInfo? = try {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            null
        }

        val declared = info?.requestedPermissions?.toList().orEmpty().sorted()
        val network = declared.filter { it in networkPermissionNames }

        val appInfo = info?.applicationInfo
        val debuggable = (appInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) ?: 0) != 0
        val backupAllowed = (appInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP) ?: 0) != 0

        return Report(
            packageName = packageName,
            versionName = info?.versionName ?: context.getString(R.string.audit_report_unknown_version),
            versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                info?.longVersionCode ?: 0L
            } else {
                @Suppress("DEPRECATION")
                (info?.versionCode ?: 0).toLong()
            },
            hasInternetPermission = declared.contains("android.permission.INTERNET"),
            networkPermissions = network,
            declaredPermissions = declared,
            apkSha256 = computeApkSha256(appInfo?.sourceDir),
            signerSha256 = computeSignerSha256(pm, packageName),
            isDebuggable = debuggable,
            backupAllowed = backupAllowed,
            biometricHardwarePresent = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT),
            sdkInt = Build.VERSION.SDK_INT,
        )
    }

    /** 流式计算 APK 的 SHA-256，避免把上百 MB 的文件读进内存。 */
    private fun computeApkSha256(sourceDir: String?): String? {
        if (sourceDir.isNullOrBlank()) return null
        return try {
            val file = java.io.File(sourceDir)
            if (!file.isFile) return null
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(128 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 签名证书 SHA-256。
     *
     * 使用 `GET_SIGNING_CERTIFICATES`（API 28+）而不是已废弃的 `GET_SIGNATURES`，
     * 前者能正确处理 APK Signature Scheme v3 的密钥轮换。
     */
    private fun computeSignerSha256(pm: PackageManager, packageName: String): String? = try {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        val info = pm.getPackageInfo(packageName, flags)
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = info.signingInfo ?: return null
            if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }
        } else {
            @Suppress("DEPRECATION")
            info.signatures
        }
        val first = signatures.firstOrNull() ?: return null
        MessageDigest.getInstance("SHA-256").digest(first.toByteArray())
            .joinToString("") { "%02x".format(it) }
    } catch (e: Exception) {
        null
    }

    /**
     * 生成可复制、可离线核对的纯文本审计报告。
     *
     * 格式刻意保持人类可读 + 机器可解析，方便用户把它贴到任何地方
     * 请第三方复核，而不必信任本应用的界面。
     *
     * **文案全部取自字符串资源**：报告是用户要贴出去给第三方看的东西，
     * 更不应该在英文界面下露出中文。因此这里用 [context] 解析资源，
     * 而不是拼接字面量。
     */
    fun renderText(report: Report, kdfDescription: String, cipherDescription: String): String {
        // 语言可能在进程生命周期内被切换（Activity 重建），因此每次都重新取字符串，
        // 不缓存 —— 复制报告是低频操作，不值得为它引入失效风险。
        val res = context.resources
        fun s(id: Int): String = res.getString(id)
        val generatedAt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
            .format(java.util.Date())

        return buildString {
            appendLine(s(R.string.audit_report_title))
            appendLine(s(R.string.audit_report_generated_at).format(generatedAt))
            appendLine()
            appendLine(s(R.string.audit_report_section_package))
            appendLine("${s(R.string.audit_report_label_package)}: ${report.packageName}")
            appendLine("${s(R.string.audit_report_label_version)}: ${report.versionName} (${report.versionCode})")
            appendLine("${s(R.string.audit_report_label_api)}: ${report.sdkInt}")
            appendLine()
            appendLine(s(R.string.audit_report_section_network))
            if (report.networkClean) {
                appendLine("${s(R.string.audit_report_label_result)}: ${s(R.string.audit_report_network_clean)}")
                appendLine(s(R.string.audit_report_network_clean_note_1))
                appendLine(s(R.string.audit_report_network_clean_note_2))
            } else {
                appendLine("${s(R.string.audit_report_label_result)}: ${s(R.string.audit_report_network_bad)}")
                report.networkPermissions.forEach { appendLine("  - $it") }
            }
            appendLine()
            appendLine(s(R.string.audit_report_section_permissions))
            if (report.declaredPermissions.isEmpty()) {
                appendLine("  ${s(R.string.audit_report_none)}")
            } else {
                report.declaredPermissions.forEach { appendLine("  - $it") }
            }
            appendLine()
            appendLine(s(R.string.audit_report_section_crypto))
            appendLine("${s(R.string.audit_report_label_kdf)}: $kdfDescription")
            appendLine("${s(R.string.audit_report_label_cipher)}: $cipherDescription")
            appendLine("${s(R.string.audit_report_label_data_key)}: ${s(R.string.audit_report_data_key_value)}")
            appendLine("${s(R.string.audit_report_label_integrity)}: ${s(R.string.audit_report_integrity_value)}")
            appendLine()
            appendLine(s(R.string.audit_report_section_apk))
            appendLine(
                "${s(R.string.audit_report_label_apk_sha256)}: " +
                    (report.apkSha256 ?: s(R.string.audit_report_unavailable_incremental)),
            )
            appendLine(
                "${s(R.string.audit_report_label_signer)}: " +
                    (report.signerSha256 ?: s(R.string.audit_report_unavailable)),
            )
            appendLine()
            appendLine(s(R.string.audit_report_section_other))
            appendLine(
                "${s(R.string.audit_report_label_debuggable)}: " +
                    s(
                        if (report.isDebuggable) R.string.audit_report_debuggable_yes
                        else R.string.audit_report_debuggable_no,
                    ),
            )
            appendLine(
                "${s(R.string.audit_report_label_system_backup)}: " +
                    s(
                        if (report.backupAllowed) R.string.audit_report_backup_allowed
                        else R.string.audit_report_backup_disabled,
                    ),
            )
            appendLine(
                "${s(R.string.audit_report_label_fingerprint_hw)}: " +
                    s(
                        if (report.biometricHardwarePresent) R.string.audit_report_hw_present
                        else R.string.audit_report_hw_absent,
                    ),
            )
        }
    }
}
