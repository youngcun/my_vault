package com.myvault.password.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.myvault.password.R
import com.myvault.password.qr.QrCodes
import com.myvault.password.qr.QrCredential
import com.myvault.password.qr.QrError
import com.myvault.password.qr.UnsupportedKind
import com.myvault.password.ui.QrImportState
import com.myvault.password.ui.components.InfoCard
import com.myvault.password.ui.components.LocalUserActivity
import com.myvault.password.ui.components.WarningCard
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ExecutorService

/**
 * 扫码导入界面。
 *
 * 交互上的一条硬规则：**扫码只是「拿到一段文本」，写入密码库永远是用户的显式动作**。
 * 相机一命中就自动入库看起来更顺滑，但代价是任何人的二维码往镜头前一晃
 * 就能改写你的密码库 —— 与自动填充「每次必须显式确认」的原则一致，这里也必须确认。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrImportScreen(
    state: QrImportState,
    onBack: () -> Unit,
    onScanResult: (String) -> Unit,
    onUnlock: (CharArray) -> Unit,
    onImport: () -> Unit,
    onRescan: () -> Unit,
    onTogglePasswordVisible: () -> Unit,
    onImported: (String) -> Unit,
) {
    val context = LocalContext.current
    val credential = state.credential
    val sealed = state.sealed
    val unsupported = state.unsupported
    val parseError = state.error

    // 导入成功后把结果交回导航层：由它回到列表并显示提示。
    // 用 LaunchedEffect 而不是直接在按钮里回调，是因为写库是异步完成的，
    // 成功时那个按钮早已不在组合里。
    LaunchedEffect(state.importedTitle) {
        state.importedTitle?.let(onImported)
    }

    // 相机权限：进入界面时若还没授权，就等用户点「授权相机」再请求。
    // 拒绝也不影响使用 —— 还可以从图片识别。
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> hasPermission = granted }

    val hasCamera = remember {
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
    }

    // 从图片识别：不需要任何存储权限，SAF 返回的 URI 就是唯一凭据。
    var pendingImage by remember { mutableStateOf<Uri?>(null) }
    var decodingImage by remember { mutableStateOf(false) }
    var imageFailed by remember { mutableStateOf(false) }
    val imagePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri != null) {
            pendingImage = uri
            decodingImage = true
            imageFailed = false
        }
    }

    // 解码放到 IO 线程：整图二值化 + 纠错是 CPU 活，主线程做会明显卡顿。
    LaunchedEffect(pendingImage) {
        val uri = pendingImage ?: return@LaunchedEffect
        val text = withContext(Dispatchers.IO) {
            runCatching { QrCodes.decodeImage(context, uri) }.getOrNull()
        }
        decodingImage = false
        pendingImage = null
        if (text != null) onScanResult(text) else imageFailed = true
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.qr_import_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    navigationIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.Default.ArrowBack,
                            contentDescription = stringResource(R.string.common_back),
                        )
                    }
                },
            )
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            when {
                credential != null -> CredentialPreviewCard(
                    credential = credential,
                    passwordVisible = state.passwordVisible,
                    duplicateSite = state.duplicateSite,
                    working = state.working,
                    saveFailed = state.saveFailed,
                    onTogglePasswordVisible = onTogglePasswordVisible,
                    onImport = onImport,
                    onRescan = onRescan,
                )

                sealed != null -> SealedUnlockCard(
                    working = state.working,
                    errorVisible = parseError == QrError.WRONG_PASSPHRASE,
                    onUnlock = onUnlock,
                    onRescan = onRescan,
                )

                unsupported != null -> UnsupportedCard(kind = unsupported)

                parseError != null -> ParseErrorCard(error = parseError)

                else -> ScanningSection(
                    hasCamera = hasCamera,
                    hasPermission = hasPermission,
                    onRequestPermission = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                    onDecoded = onScanResult,
                    decodingImage = decodingImage,
                    imageFailed = imageFailed,
                    onPickImage = { imagePicker.launch(arrayOf("image/*")) },
                )
            }

            // 只有在「拿到结果但用不了」或「解析失败」时才给「重新扫描」：
            // 相机正在取景时它没有意义（再点一次也是同一个取景画面），
            // 而解析结果卡片里已经有自己的「重新扫描」。
            if (unsupported != null || parseError != null) {
                OutlinedButton(onClick = onRescan, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.QrCodeScanner, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.qr_rescan))
                }
            }
        }
    }
}

// ================================================================== 取景与扫描

@Composable
private fun ScanningSection(
    hasCamera: Boolean,
    hasPermission: Boolean,
    onRequestPermission: () -> Unit,
    onDecoded: (String) -> Unit,
    decodingImage: Boolean,
    imageFailed: Boolean,
    onPickImage: () -> Unit,
) {
    when {
        !hasCamera -> InfoCard(title = stringResource(R.string.qr_no_camera_title)) {
            Text(
                text = stringResource(R.string.qr_no_camera_body),
                style = MaterialTheme.typography.bodySmall,
            )
        }

        !hasPermission -> CameraPermissionCard(onRequestPermission = onRequestPermission)

        else -> {
            QrCameraPreview(
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(1f)
                    .clip(RoundedCornerShape(16.dp)),
                onDecoded = onDecoded,
            )
            Text(
                text = stringResource(R.string.qr_scan_hint),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }

    if (decodingImage) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
            Spacer(Modifier.width(10.dp))
            Text(stringResource(R.string.qr_image_decoding), style = MaterialTheme.typography.bodySmall)
        }
    }
    if (imageFailed) {
        Text(
            text = stringResource(R.string.qr_image_no_code),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }

    OutlinedButton(
        onClick = onPickImage,
        enabled = !decodingImage,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Icon(Icons.Default.Image, contentDescription = null)
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.qr_from_image))
    }
    Text(
        text = stringResource(R.string.qr_from_image_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun CameraPermissionCard(onRequestPermission: () -> Unit) {
    InfoCard(title = stringResource(R.string.qr_permission_title)) {
        Text(
            text = stringResource(R.string.qr_permission_body),
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(10.dp))
        Button(onClick = onRequestPermission) {
            Icon(Icons.Default.CameraAlt, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.qr_permission_grant))
        }
    }
}

/**
 * CameraX 取景 + 逐帧识别。
 *
 * 只在这一屏存在：离开界面时 `unbindAll` 并关闭分析线程，相机立刻释放
 * （系统状态栏的相机指示器随之消失 —— 用户能看见「它确实停了」）。
 */
@Composable
private fun QrCameraPreview(
    modifier: Modifier,
    onDecoded: (String) -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentOnDecoded by rememberUpdatedState(onDecoded)

    // 在组合里创建一次 PreviewView：它是纯 View，不持有任何敏感数据，
    // 生命周期由 AndroidView 管理。
    val previewView = remember { PreviewView(context) }
    var cameraFailed by remember { mutableStateOf(false) }
    // 绑定成功后把 provider 记下来，供 onDispose 解绑 ——
    // 不在 dispose 里重新 getInstance().get()：那次 get() 可能阻塞主线程。
    val providerHolder = remember { mutableStateOf<ProcessCameraProvider?>(null) }

    val analyzer = remember {
        QrCodes.CameraAnalyzer { text -> currentOnDecoded(text) }
    }
    val executor: ExecutorService = remember { QrCodes.newAnalysisExecutor() }

    LaunchedEffect(Unit) {
        val provider = try {
            val deferred = CompletableDeferred<ProcessCameraProvider>()
            val future = ProcessCameraProvider.getInstance(context)
            future.addListener(
                {
                    runCatching { deferred.complete(future.get()) }
                        .onFailure { deferred.completeExceptionally(it) }
                },
                ContextCompat.getMainExecutor(context),
            )
            deferred.await()
        } catch (e: Exception) {
            cameraFailed = true
            return@LaunchedEffect
        }
        providerHolder.value = provider

        try {
            previewView.scaleType = PreviewView.ScaleType.FILL_CENTER
            previewView.implementationMode = PreviewView.ImplementationMode.COMPATIBLE

            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }
            val analysis = ImageAnalysis.Builder()
                // 只保留最新一帧：扫码不需要排队，积压的帧只会让画面延迟
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also { it.setAnalyzer(executor, analyzer) }

            provider.unbindAll()
            provider.bindToLifecycle(
                lifecycleOwner,
                CameraSelector.DEFAULT_BACK_CAMERA,
                preview,
                analysis,
            )
        } catch (e: Exception) {
            // 相机被其他应用占用，或设备只有前置相机
            cameraFailed = true
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            // 停掉分析并解绑相机：系统状态栏的相机指示器会随之消失
            analyzer.pause()
            providerHolder.value?.let { provider -> runCatching { provider.unbindAll() } }
            executor.shutdown()
        }
    }

    if (cameraFailed) {
        WarningCard(
            title = stringResource(R.string.qr_camera_failed_title),
            body = stringResource(R.string.qr_camera_failed_body),
        )
    } else {
        AndroidView(
            modifier = modifier.background(Color.Black),
            factory = { previewView },
        )
    }
}

// ================================================================== 结果卡片

@Composable
private fun CredentialPreviewCard(
    credential: QrCredential,
    passwordVisible: Boolean,
    duplicateSite: String?,
    working: Boolean,
    saveFailed: Boolean,
    onTogglePasswordVisible: () -> Unit,
    onImport: () -> Unit,
    onRescan: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(
                text = stringResource(R.string.qr_preview_title),
                style = MaterialTheme.typography.titleMedium,
            )
            FieldRow(stringResource(R.string.qr_preview_site), credential.site)
            FieldRow(stringResource(R.string.qr_preview_username), credential.username)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.qr_preview_password),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = when {
                            credential.password.isEmpty() -> "—"
                            passwordVisible -> credential.password
                            else -> "•".repeat(credential.password.length.coerceAtMost(16))
                        },
                        style = MaterialTheme.typography.bodyLarge,
                        fontFamily = FontFamily.Monospace,
                    )
                }
                IconButton(onClick = onTogglePasswordVisible) {
                    Icon(
                        imageVector = if (passwordVisible) {
                            Icons.Default.VisibilityOff
                        } else {
                            Icons.Default.Visibility
                        },
                        contentDescription = stringResource(
                            if (passwordVisible) R.string.qr_hide_password else R.string.qr_show_password,
                        ),
                    )
                }
            }
            FieldRow(stringResource(R.string.qr_preview_url), credential.url)
            if (credential.notes.isNotBlank()) {
                FieldRow(stringResource(R.string.qr_preview_notes), credential.notes)
            }

            if (duplicateSite != null) {
                WarningCard(
                    title = stringResource(R.string.qr_duplicate_title),
                    body = stringResource(R.string.qr_duplicate_body, duplicateSite),
                )
            }
            if (saveFailed) {
                Text(
                    text = stringResource(R.string.qr_save_failed),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            HorizontalDivider()
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(onClick = onRescan, enabled = !working) {
                    Text(stringResource(R.string.qr_rescan))
                }
                Button(onClick = onImport, enabled = !working, modifier = Modifier.weight(1f)) {
                    if (working) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                    } else {
                        Text(stringResource(R.string.qr_import_action))
                    }
                }
            }
        }
    }
}

@Composable
private fun FieldRow(label: String, value: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value.ifBlank { "—" },
            style = MaterialTheme.typography.bodyLarge,
        )
    }
}

@Composable
private fun SealedUnlockCard(
    working: Boolean,
    errorVisible: Boolean,
    onUnlock: (CharArray) -> Unit,
    onRescan: () -> Unit,
) {
    val reportUserActivity = LocalUserActivity.current
    var passphrase by remember { mutableStateOf("") }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Lock, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.qr_sealed_title),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            Text(
                text = stringResource(R.string.qr_sealed_body),
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedTextField(
                value = passphrase,
                onValueChange = {
                    reportUserActivity()
                    passphrase = it
                },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.qr_sealed_passphrase)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done,
                ),
                enabled = !working,
                isError = errorVisible,
            )
            if (errorVisible) {
                Text(
                    text = stringResource(R.string.qr_sealed_wrong),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(onClick = onRescan, enabled = !working) {
                    Text(stringResource(R.string.qr_rescan))
                }
                Button(
                    onClick = { onUnlock(passphrase.toCharArray()) },
                    enabled = !working && passphrase.isNotEmpty(),
                    modifier = Modifier.weight(1f),
                ) {
                    if (working) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                    } else {
                        Text(stringResource(R.string.qr_sealed_unlock))
                    }
                }
            }
        }
    }
}

@Composable
private fun UnsupportedCard(kind: UnsupportedKind) {
    val title = when (kind) {
        UnsupportedKind.PASSKEY_HYBRID -> stringResource(R.string.qr_unsupported_passkey_title)
        UnsupportedKind.TOTP -> stringResource(R.string.qr_unsupported_totp_title)
        UnsupportedKind.WIFI -> stringResource(R.string.qr_unsupported_wifi_title)
        UnsupportedKind.OTHER -> stringResource(R.string.qr_unsupported_other_title)
    }
    val body = when (kind) {
        UnsupportedKind.PASSKEY_HYBRID -> stringResource(R.string.qr_unsupported_passkey_body)
        UnsupportedKind.TOTP -> stringResource(R.string.qr_unsupported_totp_body)
        UnsupportedKind.WIFI -> stringResource(R.string.qr_unsupported_wifi_body)
        UnsupportedKind.OTHER -> stringResource(R.string.qr_unsupported_other_body)
    }
    WarningCard(title = title, body = body)
}

@Composable
private fun ParseErrorCard(error: QrError) {
    WarningCard(
        title = stringResource(R.string.qr_error_title),
        body = qrErrorText(error),
    )
}

/** 结构化错误 → 当前语言的文案。错误枚举在 QR 层，翻译在这里。 */
@Composable
fun qrErrorText(error: QrError): String = when (error) {
    QrError.EMPTY -> stringResource(R.string.qr_error_empty)
    QrError.TOO_LONG -> stringResource(R.string.qr_error_too_long)
    QrError.NOT_MYVAULT -> stringResource(R.string.qr_error_not_myvault)
    QrError.BAD_FORMAT -> stringResource(R.string.qr_error_bad_format)
    QrError.BAD_VERSION -> stringResource(R.string.qr_error_bad_version)
    QrError.BAD_FIELD -> stringResource(R.string.qr_error_bad_field)
    QrError.BAD_BASE64 -> stringResource(R.string.qr_error_bad_base64)
    QrError.BAD_PARAMS -> stringResource(R.string.qr_error_bad_params)
    QrError.BAD_CIPHERTEXT -> stringResource(R.string.qr_error_bad_ciphertext)
    QrError.WRONG_PASSPHRASE -> stringResource(R.string.qr_sealed_wrong)
    QrError.TOO_BIG_TO_ENCODE -> stringResource(R.string.qr_export_too_big)
    QrError.EMPTY_CREDENTIAL -> stringResource(R.string.qr_error_empty_credential)
}
