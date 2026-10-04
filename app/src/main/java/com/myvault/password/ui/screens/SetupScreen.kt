package com.myvault.password.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.myvault.password.R
import com.myvault.password.core.PasswordEntropy
import com.myvault.password.ui.components.StrengthMeter
import com.myvault.password.ui.components.WarningCard
import com.myvault.password.ui.components.crackTimeText

/**
 * 首次创建密码库。
 *
 * 界面在这里承担一个**安全职责**，而不只是收集输入：
 *  - 实时展示主密码的保守熵下界；
 *  - 在按钮下方明确写出「忘记即永久失去数据」，避免用户误以为有找回渠道；
 *  - 默认勾选「同时启用指纹解锁」，但不强制。
 */
@Composable
fun SetupScreen(
    busy: Boolean,
    errorMessage: String?,
    onCreate: (password: CharArray) -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }
    var enableBiometric by remember { mutableStateOf(false) }

    val bits = remember(password) {
        PasswordEntropy.estimateUserTypedBits(password.toCharArray())
    }
    val tooShort = password.isNotEmpty() && password.length < MIN_MASTER_LENGTH
    val mismatch = confirm.isNotEmpty() && confirm != password
    val canSubmit = password.length >= MIN_MASTER_LENGTH && confirm == password && !busy

    Scaffold { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
        ) {
            Text(
                text = stringResource(R.string.setup_title),
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                text = stringResource(R.string.setup_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 6.dp, bottom = 18.dp),
            )

            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text(stringResource(R.string.setup_password)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Next,
                ),
                visualTransformation = if (visible) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                trailingIcon = {
                    IconButton(onClick = { visible = !visible }) {
                        Icon(
                            imageVector = if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = stringResource(
                                if (visible) R.string.unlock_hide_password else R.string.unlock_show_password,
                            ),
                        )
                    }
                },
                isError = tooShort,
            )

            if (password.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                StrengthMeter(
                    bits = bits,
                    crackTime = stringResource(
                        R.string.gen_crack_time,
                        crackTimeText(PasswordEntropy.crackTimeEstimate(bits)),
                    ),
                )
            }

            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = confirm,
                onValueChange = { confirm = it },
                label = { Text(stringResource(R.string.setup_password_confirm)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done,
                ),
                visualTransformation = if (visible) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                isError = mismatch,
                supportingText = {
                    when {
                        tooShort -> Text(stringResource(R.string.setup_too_short))
                        mismatch -> Text(stringResource(R.string.setup_mismatch))
                    }
                },
            )

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(top = 6.dp),
            ) {
                Checkbox(checked = enableBiometric, onCheckedChange = { enableBiometric = it })
                Text(
                    text = stringResource(R.string.setup_enable_biometric),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            Spacer(Modifier.height(16.dp))
            WarningCard(
                title = stringResource(R.string.setup_warning_title),
                body = stringResource(R.string.setup_warning_body),
            )

            if (errorMessage != null) {
                Text(
                    text = errorMessage,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(top = 12.dp),
                )
            }

            Spacer(Modifier.height(20.dp))
            Button(
                onClick = { onCreate(password.toCharArray()) },
                enabled = canSubmit,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
            ) {
                if (busy) {
                    CircularProgressIndicator(
                        modifier = Modifier.height(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                } else {
                    Icon(Icons.Default.Check, contentDescription = null)
                    Spacer(Modifier.height(0.dp))
                    Text(
                        text = stringResource(R.string.setup_create),
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** 主密码的最小长度门槛。低于此值不允许创建。 */
const val MIN_MASTER_LENGTH = 8
