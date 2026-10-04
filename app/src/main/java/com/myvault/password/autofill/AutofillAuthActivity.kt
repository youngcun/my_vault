package com.myvault.password.autofill

import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.myvault.password.R
import kotlinx.coroutines.launch

/**
 * 自动填充认证界面。
 *
 * 这是整个自动填充链路的**安全守门人**：系统依据 `FillResponse.setAuthentication`
 * 里的 IntentSender 拉起本 Activity，用户必须通过指纹或主密码，本 Activity 才会
 * 把明文写入 `EXTRA_AUTHENTICATION_RESULT` 交还给 AutofillManager。
 *
 * 为什么这样设计是安全的
 * -------------------
 *  - 读取 `EXTRA_AUTHENTICATION_RESULT` 需要系统签名级权限
 *    （`android.permission.PROVIDE_AUTOFILL_PROCESSING_UI`），普通应用无法解析这个
 *    PendingIntent，因此即使恶意应用知道本 Activity 的名字，也无法骗出密码；
 *  - 明文只在「本 Activity 内存 → Intent extra → 系统 AutofillManager」之间传递；
 *  - 认证完成后立即 `finish()`，不保留任何状态；返回键等于取消。
 *
 * 注意本界面**只展示目标站点名**，不展示将要填充的密码 —— 认证界面本身
 * 也可能被看到，而明确展示站点名是重要的反钓鱼措施：用户能立刻发现
 * 「我以为在填 A，系统却要我给 B 的凭据」。
 */
class AutofillAuthActivity : AppCompatActivity() {

    private var usernameId: AutofillId? = null
    private var passwordId: AutofillId? = null
    private var webDomain: String? = null
    private var packageHint: String? = null

    private var promptShown = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        usernameId = intent?.getParcelableExtra(EXTRA_USERNAME_ID)
        passwordId = intent?.getParcelableExtra(EXTRA_PASSWORD_ID)
        webDomain = intent?.getStringExtra(EXTRA_WEB_DOMAIN)
        packageHint = intent?.getStringExtra(EXTRA_PACKAGE_HINT)

        if (usernameId == null && passwordId == null) {
            // 参数不完整：不猜测，直接取消
            finishWithCancel()
            return
        }
        if (!UnlockedEntryCache.isUnlocked) {
            Toast.makeText(this, R.string.autofill_locked, Toast.LENGTH_SHORT).show()
            finishWithCancel()
            return
        }

        setContent {
            MaterialTheme {
                AuthScreen(
                    siteLabel = matchedEntry()
                        ?.let { entry ->
                            com.myvault.password.ui.components.localizedDisplayTitle(
                                this@AutofillAuthActivity,
                                entry,
                            )
                        }
                        ?: getString(R.string.autofill_auth_title),
                    onBiometric = { startBiometric() },
                    onPassword = { password -> verifyMasterPassword(password) },
                    onCancel = { finishWithCancel() },
                )
            }
        }

        // 有指纹时自动弹出，减少一次点击
        if (!promptShown && canUseBiometric()) {
            promptShown = true
            startBiometric()
        }
    }

    /**
     * 重新执行一次与填充服务相同的匹配逻辑。
     *
     * 为什么不把条目 ID 通过 Intent 传过来：那样这个 Intent 会携带
     * 「哪个站点有记录」的信息。改为在此重新匹配，既保证与服务的判断一致，
     * 也让 PendingIntent 里不包含任何与具体条目绑定的数据。
     */
    private fun matchedEntry(): com.myvault.password.domain.VaultEntry? =
        UnlockedEntryCache.candidates(webDomain, packageHint).firstOrNull()

    private fun canUseBiometric(): Boolean = try {
        BiometricManager.from(this).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.BIOMETRIC_WEAK,
        ) == BiometricManager.BIOMETRIC_SUCCESS
    } catch (e: Exception) {
        false
    }

    /**
     * 指纹认证。
     *
     * 这里的指纹只用于证明「是本人正在操作」，不参与密钥运算 —— 因为解锁后的
     * 明文快照已经在内存里。若库是锁定的，本界面根本走不到这一步
     * （`isUnlocked` 检查会先拦下）。
     */
    private fun startBiometric() {
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    deliverFill()
                }

                override fun onAuthenticationError(code: Int, errString: CharSequence) {
                    // 用户取消不视为错误，留在界面让他改用主密码
                    if (code == BiometricPrompt.ERROR_LOCKOUT ||
                        code == BiometricPrompt.ERROR_LOCKOUT_PERMANENT
                    ) {
                        Toast.makeText(
                            this@AutofillAuthActivity,
                            R.string.unlock_biometric_failed,
                            Toast.LENGTH_SHORT,
                        ).show()
                    }
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.autofill_auth_title))
            .setSubtitle(getString(R.string.autofill_auth_subtitle))
            .setNegativeButtonText(getString(R.string.common_cancel))
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.BIOMETRIC_WEAK,
            )
            .build()
        prompt.authenticate(info)
    }

    /**
     * 主密码回退路径。
     *
     * 校验方式：用主密码尝试解开当前密钥信封。这样做复用了**唯一的口令真值来源** ——
     * 我们不需要、也不应该为自动填充单独维护一份口令哈希。
     */
    private fun verifyMasterPassword(password: CharArray) {
        lifecycleScope.launch {
            val ok = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                runCatching {
                    val container = com.myvault.password.AppContainer.from(applicationContext)
                    val row = container.dao.loadEnvelope() ?: return@runCatching false
                    val env = com.myvault.password.core.EnvelopeCodec.fromJson(row.json)
                    // 解出的密钥材料只用于验证口令，立即销毁
                    com.myvault.password.core.EnvelopeCodec.unwrap(env, password).destroy()
                    true
                }.getOrDefault(false)
            }
            com.myvault.password.core.CryptoPrimitives.destroy(password)
            if (ok) {
                deliverFill()
            } else {
                Toast.makeText(
                    this@AutofillAuthActivity,
                    R.string.unlock_wrong_password,
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    /**
     * 构造并交还填充结果。
     *
     * 系统要求认证结果是一个完整的 [FillResponse]，且其中的 Dataset 必须与
     * 原始请求的字段 ID 一致。这里只填充匹配到的那一条记录。
     */
    private fun deliverFill() {
        val entry = matchedEntry()
        if (entry == null) {
            finishWithCancel()
            return
        }

        val views = RemoteViews(packageName, R.layout.autofill_dataset).apply {
            setTextViewText(
                R.id.autofill_title,
                com.myvault.password.ui.components.localizedDisplayTitle(
                    this@AutofillAuthActivity,
                    entry,
                ),
            )
            setTextViewText(
                R.id.autofill_subtitle,
                entry.username.ifBlank { getString(R.string.autofill_service_label) },
            )
        }

        val dataset = Dataset.Builder(views).apply {
            usernameId?.let { setValue(it, AutofillValue.forText(entry.username)) }
            passwordId?.let { setValue(it, AutofillValue.forText(entry.password)) }
        }.build()

        val response = FillResponse.Builder().addDataset(dataset).build()

        setResult(
            RESULT_OK,
            android.content.Intent().apply {
                putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
            },
        )
        finish()
    }

    private fun finishWithCancel() {
        setResult(RESULT_CANCELED)
        finish()
    }

    /** 返回键等同于取消：绝不能出现「按返回键就绕过认证」的路径。 */
    @Deprecated("Base method still works for all supported API levels")
    override fun onBackPressed() {
        finishWithCancel()
    }

    companion object {
        const val EXTRA_USERNAME_ID = "com.myvault.password.extra.USERNAME_ID"
        const val EXTRA_PASSWORD_ID = "com.myvault.password.extra.PASSWORD_ID"
        const val EXTRA_WEB_DOMAIN = "com.myvault.password.extra.WEB_DOMAIN"
        const val EXTRA_PACKAGE_HINT = "com.myvault.password.extra.PACKAGE_HINT"
    }
}

/**
 * 认证界面 UI。
 *
 * 保持极简：一句「你正在为哪个站点填充」、一个指纹按钮、一个主密码输入框。
 */
@Composable
private fun AuthScreen(
    siteLabel: String,
    onBiometric: () -> Unit,
    onPassword: (CharArray) -> Unit,
    onCancel: () -> Unit,
) {
    var password by remember { mutableStateOf("") }

    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = stringResource(R.string.autofill_auth_title),
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                text = siteLabel,
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(vertical = 8.dp),
            )
            Text(
                text = stringResource(R.string.autofill_auth_subtitle),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 16.dp),
            )

            Button(onClick = onBiometric, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.unlock_with_biometric))
            }

            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text(stringResource(R.string.unlock_master_password)) },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp),
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done,
                ),
                keyboardActions = KeyboardActions(
                    onDone = { if (password.isNotEmpty()) onPassword(password.toCharArray()) },
                ),
            )

            Button(
                onClick = { onPassword(password.toCharArray()) },
                enabled = password.isNotEmpty(),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp),
            ) {
                Text(stringResource(R.string.common_confirm))
            }

            TextButton(onClick = onCancel, modifier = Modifier.padding(top = 6.dp)) {
                Text(stringResource(R.string.common_cancel))
            }
        }
    }
}
