package com.myvault.password.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.myvault.password.R
import com.myvault.password.core.PasswordEntropy
import com.myvault.password.core.PasswordPolicy
import com.myvault.password.ui.EntryEditState
import com.myvault.password.ui.components.LocalUserActivity
import com.myvault.password.ui.components.StrengthMeter
import com.myvault.password.ui.components.crackTimeText
import com.myvault.password.ui.components.localizedDisplayTitle
import com.myvault.password.ui.components.policyErrorText

/**
 * 条目编辑界面。
 *
 * 密码字段默认可见（新建条目时）—— 这是有意的：用户在保存前应该**看一眼**
 * 自己将使用的密码，而不是被一排圆点糊弄过去。也正因如此，界面提供了
 * 「生成」按钮，鼓励用户在需要新密码时让工具生成而不是自己编。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryEditScreen(
    state: EntryEditState,
    onBack: () -> Unit,
    onSiteChange: (String) -> Unit,
    onUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onUrlChange: (String) -> Unit,
    onNotesChange: (String) -> Unit,
    onTogglePasswordVisible: () -> Unit,
    onToggleFavorite: () -> Unit,
    onRegenerate: () -> Unit,
    onPolicyChange: (PasswordPolicy) -> Unit,
    onSave: () -> Unit,
    onDelete: () -> Unit,
    onConsumeError: () -> Unit,
) {
    var confirmDelete by remember { mutableStateOf(false) }
    var generatorOpen by remember { mutableStateOf(false) }

    val policyBits = remember(state.policy) { PasswordEntropy.bitsOf(state.policy) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(state.titleRes)) },
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
                    IconButton(onClick = onToggleFavorite) {
                        Icon(
                            imageVector = if (state.entry.favorite) Icons.Default.Star else Icons.Default.StarBorder,
                            contentDescription = stringResource(R.string.entry_favorite_toggle),
                        )
                    }
                    if (!state.isNew) {
                        IconButton(onClick = { confirmDelete = true }) {
                            Icon(
                                Icons.Default.Delete,
                                contentDescription = stringResource(R.string.entry_delete),
                            )
                        }
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
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            // 每一个字符都算一次用户交互：软键盘（IME）提交文字**不产生指针事件**，
            // 若不上报，「慢慢敲一条带备注的条目」会被自动锁定判定为闲置 ——
            // 而锁定会销毁导航图，尚未保存的编辑内容随之丢失（详见 LocalUserActivity）。
            val reportUserActivity = LocalUserActivity.current

            OutlinedTextField(
                value = state.entry.site,
                onValueChange = { reportUserActivity(); onSiteChange(it) },
                label = { Text(stringResource(R.string.entry_site)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                isError = state.error != null && state.entry.site.isBlank(),
            )

            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = state.entry.username,
                onValueChange = { reportUserActivity(); onUsernameChange(it) },
                label = { Text(stringResource(R.string.entry_username)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Email,
                    imeAction = ImeAction.Next,
                ),
            )

            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = state.entry.password,
                onValueChange = { reportUserActivity(); onPasswordChange(it) },
                label = { Text(stringResource(R.string.entry_password)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Next,
                ),
                visualTransformation = if (state.passwordVisible) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                trailingIcon = {
                    Row {
                        IconButton(onClick = onTogglePasswordVisible) {
                            Icon(
                                imageVector = if (state.passwordVisible) {
                                    Icons.Default.VisibilityOff
                                } else {
                                    Icons.Default.Visibility
                                },
                                contentDescription = stringResource(
                                    if (state.passwordVisible) R.string.entry_hide else R.string.entry_reveal,
                                ),
                            )
                        }
                    }
                },
            )

            Spacer(Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = onRegenerate,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.Refresh, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.entry_generate))
                }
                OutlinedButton(
                    onClick = { generatorOpen = true },
                    modifier = Modifier.weight(1f),
                ) {
                    Text(stringResource(R.string.gen_title))
                }
            }

            Spacer(Modifier.height(6.dp))
            StrengthMeter(
                bits = state.entry.password
                    .takeIf { it.isNotEmpty() }
                    ?.let { PasswordEntropy.estimateUserTypedBits(it.toCharArray()) }
                    ?: 0.0,
                showBits = true,
            )

            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = state.entry.url,
                onValueChange = { reportUserActivity(); onUrlChange(it) },
                label = { Text(stringResource(R.string.entry_url)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Next,
                ),
                supportingText = { Text(stringResource(R.string.entry_url_hint)) },
            )

            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = state.entry.notes,
                onValueChange = { reportUserActivity(); onNotesChange(it) },
                label = { Text(stringResource(R.string.entry_notes)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(120.dp),
                supportingText = { Text(stringResource(R.string.entry_notes_hint)) },
            )

            // 两类错误都显示：state.error 是「保存/删除失败」等已渲染好的字符串，
            // state.policyError 是生成器策略不可行 —— 后者必须**在这里**按当前语言
            // 渲染（不能提前渲染进状态，否则切换语言后会残留旧语言）。
            val policyMessage = state.policyError?.let { policyErrorText(it) }
            val shownError = state.error ?: policyMessage
            if (shownError != null) {
                Spacer(Modifier.height(8.dp))
                Text(
                    text = shownError,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.clickable(onClick = onConsumeError),
                )
            }

            Spacer(Modifier.height(20.dp))
            Button(
                onClick = onSave,
                enabled = state.entry.site.isNotBlank() &&
                    state.entry.password.isNotEmpty() &&
                    !state.working,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
            ) {
                if (state.working) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.height(0.dp))
                    Text(
                        text = stringResource(R.string.entry_saving),
                        modifier = Modifier.padding(start = 8.dp),
                    )
                } else {
                    Text(stringResource(R.string.entry_save))
                }
            }
            Spacer(Modifier.height(28.dp))
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.entry_delete)) },
            text = { Text(stringResource(R.string.entry_delete_confirm, localizedDisplayTitle(state.entry))) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    onDelete()
                }) {
                    Text(stringResource(R.string.entry_delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) {
                    Text(stringResource(R.string.entry_cancel))
                }
            },
        )
    }

    if (generatorOpen) {
        // 复用同一个策略面板，保证与独立生成器行为一致
        AlertDialog(
            onDismissRequest = { generatorOpen = false },
            title = { Text(stringResource(R.string.gen_title)) },
            text = {
                Column(
                    modifier = Modifier
                        .verticalScroll(rememberScrollState())
                        .fillMaxWidth(),
                ) {
                    StrengthMeter(
                        bits = policyBits,
                        crackTime = stringResource(
                            R.string.gen_crack_time,
                            crackTimeText(PasswordEntropy.crackTimeEstimate(policyBits)),
                        ),
                    )
                    Spacer(Modifier.height(12.dp))
                    PolicyEditor(policy = state.policy, onPolicyChange = onPolicyChange)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    onRegenerate()
                    generatorOpen = false
                }) {
                    Text(stringResource(R.string.gen_use))
                }
            },
            dismissButton = {
                TextButton(onClick = { generatorOpen = false }) {
                    Text(stringResource(R.string.common_cancel))
                }
            },
        )
    }
}
