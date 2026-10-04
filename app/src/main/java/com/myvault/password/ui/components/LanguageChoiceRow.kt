package com.myvault.password.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Language
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.myvault.password.R
import com.myvault.password.settings.AppLanguage

/** 语言选项的显示文案。语言名本身永远用该语言自己的写法（中文写「简体中文」，英文写「English」）。 */
@Composable
fun languageLabel(language: AppLanguage): String = stringResource(
    when (language) {
        AppLanguage.SYSTEM -> R.string.settings_language_system
        AppLanguage.CHINESE -> R.string.settings_language_zh
        AppLanguage.ENGLISH -> R.string.settings_language_en
    },
)

/**
 * 界面语言选择行。
 *
 * 这里不复用 [SettingsScreen] 里的通用 `ChoiceRow`：那个组件的选中判定是
 * 「显示文案相等」（`label == current`），对自动锁定这类「数值 → 文案」的映射
 * 是够用的，但语言选项更适合直接按枚举比较 —— 万一将来两种语言的显示名
 * 恰好相同（例如都以 "English" 呈现），按文案比较会同时勾选两项。
 */
@Composable
fun LanguageChoiceRow(
    current: AppLanguage,
    onSelect: (AppLanguage) -> Unit,
) {
    var open by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { open = true }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Default.Language,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(22.dp),
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 14.dp),
        ) {
            Text(
                text = stringResource(R.string.settings_language),
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = languageLabel(current),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
    }

    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            title = { Text(stringResource(R.string.settings_language)) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    AppLanguage.entries.forEach { option ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    onSelect(option)
                                    open = false
                                }
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                // 按枚举比较，而不是按显示文案 —— 见上面的说明。
                                selected = option == current,
                                onClick = {
                                    onSelect(option)
                                    open = false
                                },
                            )
                            Text(languageLabel(option), modifier = Modifier.padding(start = 4.dp))
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                androidx.compose.material3.TextButton(onClick = { open = false }) {
                    Text(stringResource(R.string.common_cancel))
                }
            },
        )
    }
}
