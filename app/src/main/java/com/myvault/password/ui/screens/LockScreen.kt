package com.myvault.password.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.myvault.password.R

/**
 * 解锁界面。
 *
 * 支持两条路径：主密码（唯一权威）与指纹（便利，但同样由密钥信封保护）。
 * 界面刻意不显示「已输入多少次错误密码」之类的计数器 —— 那会泄露信息，
 * 而且在线暴力破解对本应用没有意义（每次尝试都要跑一遍 Argon2id）。
 */
@Composable
fun LockScreen(
    busy: Boolean,
    errorMessage: String?,
    biometricEnrolled: Boolean,
    biometricReady: Boolean,
    onUnlock: (CharArray) -> Unit,
    onBiometric: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }

    Scaffold { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                imageVector = Icons.Default.Lock,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.height(56.dp),
            )
            Spacer(Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.unlock_title),
                style = MaterialTheme.typography.headlineSmall,
            )
            Text(
                text = stringResource(R.string.unlock_subtitle),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 8.dp, bottom = 24.dp),
            )

            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text(stringResource(R.string.unlock_master_password)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done,
                ),
                keyboardActions = KeyboardActions(
                    onDone = { if (password.isNotEmpty()) onUnlock(password.toCharArray()) },
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
                isError = errorMessage != null,
                supportingText = { if (errorMessage != null) Text(errorMessage) },
            )

            Spacer(Modifier.height(16.dp))
            Button(
                onClick = { onUnlock(password.toCharArray()) },
                enabled = password.isNotEmpty() && !busy,
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
                    Text(
                        text = stringResource(R.string.unlock_working),
                        modifier = Modifier.padding(start = 10.dp),
                    )
                } else {
                    Text(stringResource(R.string.unlock_button))
                }
            }

            if (biometricEnrolled && biometricReady) {
                Spacer(Modifier.height(12.dp))
                OutlinedButton(
                    onClick = onBiometric,
                    enabled = !busy,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                ) {
                    Icon(Icons.Default.Fingerprint, contentDescription = null)
                    Text(
                        text = stringResource(R.string.unlock_with_biometric),
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }
            }

            Spacer(Modifier.height(20.dp))
            Text(
                text = stringResource(R.string.unlock_attempts_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
