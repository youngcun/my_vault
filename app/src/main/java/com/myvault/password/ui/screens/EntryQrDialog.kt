package com.myvault.password.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.myvault.password.R
import com.myvault.password.domain.VaultEntry
import com.myvault.password.qr.CredentialQr
import com.myvault.password.qr.QrCodes
import com.myvault.password.qr.QrCredential
import com.myvault.password.qr.QrError
import com.myvault.password.qr.QrFormatException
import com.myvault.password.ui.components.LocalUserActivity
import com.myvault.password.ui.components.WarningCard
import com.myvault.password.ui.components.localizedDisplayTitle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** 二维码最小口令长度。太短的口令对离线爆破几乎没有抵抗，等于没加密。 */
private const val MIN_QR_PASSPHRASE = 8

/**
 * 把一条凭据显示成二维码。
 *
 * 为什么默认是「口令加密」而不是明文：二维码是一个**广播介质** ——
 * 屏幕上显示出来的东西，房间里任何一台设备都能拍到，截图还会留在相册里。
 * 明文模式仍然保留（当面把密码递给自己的另一台设备很常见），但必须由用户
 * 主动选择，并且明确看到代价。
 */
@Composable
fun EntryQrDialog(
    entry: VaultEntry,
    onDismiss: () -> Unit,
) {
    val reportUserActivity = LocalUserActivity.current

    var sealed by remember { mutableStateOf(true) }
    var passphrase by remember { mutableStateOf("") }
    var passphraseVisible by remember { mutableStateOf(true) }
    var working by remember { mutableStateOf(false) }
    var image by remember { mutableStateOf<ImageBitmap?>(null) }
    var error by remember { mutableStateOf<QrError?>(null) }
    var tooShort by remember { mutableStateOf(false) }

    val credential = remember(entry) {
        QrCredential(
            site = entry.site,
            username = entry.username,
            password = entry.password,
            url = entry.url,
            notes = entry.notes,
        )
    }

    // 生成：Argon2id（加密模式）与二维码编码都是 CPU 活，必须离开主线程。
    LaunchedEffect(working) {
        if (!working) return@LaunchedEffect
        val result = withContext(Dispatchers.Default) {
            runCatching {
                val payload = if (sealed) {
                    CredentialQr.encodeSealed(credential, passphrase.toCharArray())
                } else {
                    CredentialQr.encodePlain(credential)
                }
                QrCodes.encode(payload)
            }
        }
        working = false
        result.fold(
            onSuccess = { bitmap ->
                if (bitmap == null) {
                    error = QrError.TOO_BIG_TO_ENCODE
                } else {
                    image = bitmap.asImageBitmap()
                    error = null
                }
            },
            onFailure = { e ->
                error = (e as? QrFormatException)?.error ?: QrError.BAD_FORMAT
            },
        )
    }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(20.dp),
            tonalElevation = 6.dp,
        ) {
            Column(
                modifier = Modifier
                    .padding(20.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = stringResource(R.string.qr_export_title),
                    style = MaterialTheme.typography.titleLarge,
                )
                Text(
                    text = localizedDisplayTitle(entry),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                val current = image
                if (current != null) {
                    // 二维码必须是黑字白底：跟随深色主题会让部分扫码器无法二值化。
                    // 因此这里刻意固定成白色卡片，而不是用主题的 surface 色。
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .aspectRatio(1f)
                            .background(Color.White, RoundedCornerShape(12.dp))
                            .padding(12.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Image(
                            bitmap = current,
                            contentDescription = stringResource(R.string.qr_export_title),
                            modifier = Modifier.fillMaxWidth().aspectRatio(1f),
                            contentScale = ContentScale.Fit,
                        )
                    }
                    Text(
                        text = stringResource(
                            if (sealed) R.string.qr_export_caption_sealed else R.string.qr_export_caption_plain,
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (!sealed) {
                        WarningCard(
                            title = stringResource(R.string.qr_export_plain_warning_title),
                            body = stringResource(R.string.qr_export_plain_warning_body),
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedButton(
                            onClick = { image = null },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(stringResource(R.string.qr_export_again))
                        }
                        Button(onClick = onDismiss, modifier = Modifier.weight(1f)) {
                            Text(stringResource(R.string.common_close))
                        }
                    }
                } else {
                    Text(
                        text = stringResource(R.string.qr_export_body),
                        style = MaterialTheme.typography.bodySmall,
                    )

                    ModeRow(
                        selected = sealed,
                        title = stringResource(R.string.qr_export_mode_sealed),
                        detail = stringResource(R.string.qr_export_mode_sealed_detail),
                        onSelect = { sealed = true },
                    )
                    ModeRow(
                        selected = !sealed,
                        title = stringResource(R.string.qr_export_mode_plain),
                        detail = stringResource(R.string.qr_export_mode_plain_detail),
                        onSelect = { sealed = false },
                    )

                    if (sealed) {
                        OutlinedTextField(
                            value = passphrase,
                            onValueChange = {
                                reportUserActivity()
                                passphrase = it
                                tooShort = false
                            },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text(stringResource(R.string.qr_export_passphrase)) },
                            singleLine = true,
                            visualTransformation = if (passphraseVisible) {
                                VisualTransformation.None
                            } else {
                                PasswordVisualTransformation()
                            },
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Password,
                                imeAction = ImeAction.Done,
                            ),
                            isError = tooShort,
                            supportingText = {
                                Text(
                                    text = if (tooShort) {
                                        stringResource(R.string.qr_export_passphrase_short, MIN_QR_PASSPHRASE)
                                    } else {
                                        stringResource(R.string.qr_export_passphrase_hint, MIN_QR_PASSPHRASE)
                                    },
                                )
                            },
                            trailingIcon = {
                                // 用图标而不是文字按钮：文字会把这个窄输入框的标签挤成
                                // 两三行（实测「QR passphrase」被挤成三行，很难看）。
                                IconButton(onClick = { passphraseVisible = !passphraseVisible }) {
                                    Icon(
                                        imageVector = if (passphraseVisible) {
                                            Icons.Default.VisibilityOff
                                        } else {
                                            Icons.Default.Visibility
                                        },
                                        contentDescription = stringResource(
                                            if (passphraseVisible) {
                                                R.string.qr_hide_password
                                            } else {
                                                R.string.qr_show_password
                                            },
                                        ),
                                    )
                                }
                            },
                        )
                    }

                    val reason = error
                    if (reason != null) {
                        Text(
                            text = qrErrorText(reason),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }

                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedButton(onClick = onDismiss, modifier = Modifier.weight(1f)) {
                            Text(stringResource(R.string.common_cancel))
                        }
                        Button(
                            onClick = {
                                if (sealed && passphrase.length < MIN_QR_PASSPHRASE) {
                                    tooShort = true
                                } else {
                                    working = true
                                }
                            },
                            enabled = !working,
                            modifier = Modifier.weight(1f),
                        ) {
                            if (working) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(18.dp),
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.onPrimary,
                                )
                            } else {
                                Text(stringResource(R.string.qr_export_generate))
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ModeRow(
    selected: Boolean,
    title: String,
    detail: String,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, onClick = onSelect)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(selected = selected, onClick = onSelect)
        Spacer(Modifier.width(4.dp))
        Column(Modifier.padding(top = 10.dp)) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
    Spacer(Modifier.height(2.dp))
}
