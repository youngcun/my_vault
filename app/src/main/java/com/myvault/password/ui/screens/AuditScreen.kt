package com.myvault.password.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.myvault.password.R
import com.myvault.password.audit.SecurityAudit
import com.myvault.password.data.IntegrityReport

/**
 * 安全自证界面。
 *
 * 页面结构有意按「用户能验证什么」组织，而不是按「我们做了什么」组织：
 *  - 网络权限（可被系统层面验证）
 *  - 完整权限清单（可与 aapt dump permissions 对照）
 *  - 加密参数（可与源码对照）
 *  - 库完整性（可点击重跑）
 *  - APK 与签名指纹（可与官方发布值对照）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuditScreen(
    report: SecurityAudit.Report?,
    integrity: IntegrityReport?,
    verifying: Boolean,
    kdfDescription: String,
    cipherDescription: String,
    onBack: () -> Unit,
    onVerify: () -> Unit,
    onCopyReport: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.audit_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    navigationIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    actionIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.common_back))
                    }
                },
                actions = {
                    IconButton(onClick = onCopyReport) {
                        Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.audit_copy))
                    }
                },
            )
        },
    ) { inner ->
        if (report == null) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(inner),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                CircularProgressIndicator()
                Spacer(Modifier.height(12.dp))
                Text(stringResource(R.string.common_loading))
            }
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            Text(
                text = stringResource(R.string.audit_intro),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))

            // ------------------------------------------------ 网络权限
            VerdictCard(
                ok = report.networkClean,
                title = stringResource(R.string.audit_network_title),
                body = stringResource(
                    if (report.networkClean) R.string.audit_network_ok else R.string.audit_network_bad,
                ),
            )

            Spacer(Modifier.height(16.dp))
            SectionTitle(stringResource(R.string.audit_permissions_title))
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(12.dp)) {
                    if (report.declaredPermissions.isEmpty()) {
                        Text(
                            stringResource(R.string.audit_permissions_none),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    } else {
                        report.declaredPermissions.forEach { perm ->
                            Text(
                                text = "• " + perm.removePrefix("android.permission."),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                            )
                        }
                    }
                }
            }

            // ------------------------------------------------ 加密参数
            Spacer(Modifier.height(16.dp))
            SectionTitle(stringResource(R.string.audit_crypto_title))
            KeyValue(stringResource(R.string.audit_kdf), kdfDescription)
            KeyValue(stringResource(R.string.audit_cipher), cipherDescription)
            KeyValue(stringResource(R.string.audit_integrity), stringResource(R.string.audit_integrity_value))
            KeyValue(stringResource(R.string.audit_key_size), stringResource(R.string.audit_key_size_value))

            // ------------------------------------------------ 完整性
            Spacer(Modifier.height(16.dp))
            SectionTitle(stringResource(R.string.audit_integrity_title))
            if (integrity == null) {
                Text(
                    text = stringResource(R.string.audit_integrity_pending),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                VerdictCard(
                    ok = integrity.ok,
                    title = stringResource(
                        if (integrity.ok) R.string.audit_integrity_passed
                        else R.string.audit_integrity_not_passed,
                    ),
                    body = if (integrity.ok) {
                        stringResource(R.string.audit_integrity_ok, integrity.totalEntries)
                    } else {
                        stringResource(R.string.audit_integrity_failed, integrity.badEntries.size)
                    },
                )
                Spacer(Modifier.height(6.dp))
                KeyValue(
                    stringResource(R.string.audit_integrity_total),
                    integrity.totalEntries.toString(),
                )
                KeyValue(
                    stringResource(R.string.audit_integrity_checksum),
                    integrity.actualChecksum.take(32) + "…",
                )
                KeyValue(
                    stringResource(R.string.audit_integrity_checked_at),
                    formatTimestamp(System.currentTimeMillis()),
                )
                if (integrity.badEntries.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = stringResource(
                            R.string.audit_integrity_bad_entries,
                            integrity.badEntries.joinToString("\n"),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            Button(onClick = onVerify, enabled = !verifying) {
                if (verifying) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.height(0.dp))
                    Text(
                        stringResource(R.string.audit_integrity_running),
                        modifier = Modifier.padding(start = 8.dp),
                    )
                } else {
                    Text(stringResource(R.string.audit_integrity_run))
                }
            }

            // ------------------------------------------------ APK 信息
            Spacer(Modifier.height(16.dp))
            SectionTitle(stringResource(R.string.audit_apk_title))
            KeyValue(stringResource(R.string.audit_apk_package), report.packageName)
            KeyValue(
                stringResource(R.string.audit_apk_version),
                "${report.versionName} (${report.versionCode})",
            )
            KeyValue(
                stringResource(R.string.audit_apk_sha256),
                report.apkSha256 ?: stringResource(R.string.audit_apk_sha256_unavailable),
                mono = true,
            )
            KeyValue(
                stringResource(R.string.audit_signer_title),
                report.signerSha256 ?: stringResource(R.string.audit_signer_unavailable),
                mono = true,
            )

            // ------------------------------------------------ 其他
            Spacer(Modifier.height(16.dp))
            VerdictCard(
                ok = !report.isDebuggable,
                title = stringResource(R.string.audit_debug_title),
                body = stringResource(
                    if (report.isDebuggable) R.string.audit_debug_on else R.string.audit_debug_off,
                ),
            )
            Spacer(Modifier.height(10.dp))
            VerdictCard(
                ok = !report.backupAllowed,
                title = stringResource(R.string.audit_backup_title),
                body = stringResource(R.string.audit_backup_off),
            )

            Spacer(Modifier.height(16.dp))
            SectionTitle(stringResource(R.string.audit_dependencies_title))
            Text(
                text = stringResource(R.string.audit_dependencies_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(28.dp))
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(bottom = 6.dp),
    )
}

@Composable
private fun KeyValue(label: String, value: String, mono: Boolean = false) {
    Column(Modifier.padding(vertical = 3.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
        )
    }
}

@Composable
private fun VerdictCard(ok: Boolean, title: String, body: String) {
    val container = if (ok) {
        MaterialTheme.colorScheme.secondaryContainer
    } else {
        MaterialTheme.colorScheme.errorContainer
    }
    val onContainer = if (ok) {
        MaterialTheme.colorScheme.onSecondaryContainer
    } else {
        MaterialTheme.colorScheme.onErrorContainer
    }
    Surface(
        color = container,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Icon(
                imageVector = if (ok) Icons.Default.CheckCircle else Icons.Default.Cancel,
                contentDescription = null,
                tint = onContainer,
            )
            Column(Modifier.padding(start = 10.dp)) {
                Text(text = title, style = MaterialTheme.typography.titleSmall, color = onContainer)
                Text(
                    text = body,
                    style = MaterialTheme.typography.bodySmall,
                    color = onContainer,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
    }
}
