package com.myvault.password.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.myvault.password.R
import com.myvault.password.core.PasswordEntropy
import com.myvault.password.core.PasswordPolicy
import com.myvault.password.core.WordList
import com.myvault.password.ui.components.StrengthMeter
import com.myvault.password.ui.components.crackTimeText

/**
 * 密码生成器的策略面板。
 *
 * 这个组合项被两个地方复用：
 *  1. 独立的「生成器」界面；
 *  2. 新建/编辑条目时的「生成」按钮弹出的底部面板。
 *
 * 复用的意义不只是省代码 —— 它保证「生成器」与「新建条目」永远使用
 * **同一套策略语义**，不会出现两处对「长度」理解不一致的问题。
 */
@Composable
fun PolicyEditor(
    policy: PasswordPolicy,
    onPolicyChange: (PasswordPolicy) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        // ---------------------------------------------------------- 类型选择
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            val modes = listOf(
                PasswordPolicy.Mode.RANDOM to stringResource(R.string.gen_mode_random),
                PasswordPolicy.Mode.PASSPHRASE to stringResource(R.string.gen_mode_passphrase),
                PasswordPolicy.Mode.PIN to stringResource(R.string.gen_mode_pin),
            )
            modes.forEachIndexed { index, (mode, label) ->
                SegmentedButton(
                    selected = policy.mode == mode,
                    onClick = { onPolicyChange(policy.copy(mode = mode)) },
                    shape = SegmentedButtonDefaults.itemShape(index = index, count = modes.size),
                ) {
                    Text(label, style = MaterialTheme.typography.labelMedium)
                }
            }
        }

        Spacer(Modifier.height(16.dp))

        // ---------------------------------------------------------- 长度 / 词数
        when (policy.mode) {
            PasswordPolicy.Mode.RANDOM -> {
                LengthSlider(
                    label = stringResource(R.string.gen_length),
                    value = policy.safeLength,
                    range = PasswordPolicy.MIN_RANDOM_LENGTH..PasswordPolicy.MAX_RANDOM_LENGTH,
                    onChange = { onPolicyChange(policy.copy(length = it)) },
                )
            }
            PasswordPolicy.Mode.PASSPHRASE -> {
                LengthSlider(
                    label = stringResource(R.string.gen_word_count),
                    value = policy.safeLength,
                    range = PasswordPolicy.MIN_WORD_COUNT..PasswordPolicy.MAX_WORD_COUNT,
                    onChange = { onPolicyChange(policy.copy(length = it)) },
                )
            }
            PasswordPolicy.Mode.PIN -> {
                LengthSlider(
                    label = stringResource(R.string.gen_digits),
                    value = policy.safeLength,
                    range = PasswordPolicy.MIN_PIN_LENGTH..PasswordPolicy.MAX_PIN_LENGTH,
                    onChange = { onPolicyChange(policy.copy(length = it)) },
                )
            }
        }

        Spacer(Modifier.height(8.dp))

        // ---------------------------------------------------------- 各模式选项
        when (policy.mode) {
            PasswordPolicy.Mode.RANDOM -> {
                ToggleRow(
                    label = stringResource(R.string.gen_lowercase),
                    checked = policy.useLowercase,
                    onChange = { onPolicyChange(policy.copy(useLowercase = it)) },
                )
                ToggleRow(
                    label = stringResource(R.string.gen_uppercase),
                    checked = policy.useUppercase,
                    onChange = { onPolicyChange(policy.copy(useUppercase = it)) },
                )
                ToggleRow(
                    label = stringResource(R.string.gen_digits_option),
                    checked = policy.useDigits,
                    onChange = { onPolicyChange(policy.copy(useDigits = it)) },
                )
                ToggleRow(
                    label = stringResource(R.string.gen_symbols),
                    checked = policy.useSymbols,
                    onChange = { onPolicyChange(policy.copy(useSymbols = it)) },
                )
                ToggleRow(
                    label = stringResource(R.string.gen_require_each_class),
                    checked = policy.requireEachClass,
                    onChange = { onPolicyChange(policy.copy(requireEachClass = it)) },
                )
                ToggleRow(
                    label = stringResource(R.string.gen_avoid_ambiguous),
                    checked = policy.avoidAmbiguous,
                    onChange = { onPolicyChange(policy.copy(avoidAmbiguous = it)) },
                )
            }

            PasswordPolicy.Mode.PASSPHRASE -> {
                ToggleRow(
                    label = stringResource(R.string.gen_capitalize),
                    checked = policy.capitalizeWords,
                    onChange = { onPolicyChange(policy.copy(capitalizeWords = it)) },
                )
                ToggleRow(
                    label = stringResource(R.string.gen_append_digits),
                    checked = policy.appendDigitsToWords,
                    onChange = { onPolicyChange(policy.copy(appendDigitsToWords = it)) },
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.gen_wordlist_size),
                    style = MaterialTheme.typography.labelLarge,
                )
                Row(
                    modifier = Modifier.padding(top = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    FilterChip(
                        selected = policy.wordListSize == WordList.CORE_SIZE,
                        onClick = { onPolicyChange(policy.copy(wordListSize = WordList.CORE_SIZE)) },
                        label = { Text(stringResource(R.string.gen_wordlist_core)) },
                    )
                    FilterChip(
                        selected = policy.wordListSize == WordList.EXTENDED_SIZE,
                        onClick = { onPolicyChange(policy.copy(wordListSize = WordList.EXTENDED_SIZE)) },
                        label = { Text(stringResource(R.string.gen_wordlist_extended)) },
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.gen_separator) + "：${policy.separator}",                    style = MaterialTheme.typography.labelLarge,
                )
                Row(
                    modifier = Modifier.padding(top = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    listOf("-", ".", "_", " ").forEach { sep ->
                        FilterChip(
                            selected = policy.separator == sep,
                            onClick = { onPolicyChange(policy.copy(separator = sep)) },
                            label = { Text(if (sep == " ") "␣" else sep, fontFamily = FontFamily.Monospace) },
                        )
                    }
                }
            }

            PasswordPolicy.Mode.PIN -> {
                ToggleRow(
                    label = stringResource(R.string.gen_avoid_ambiguous),
                    checked = policy.avoidAmbiguous,
                    onChange = { onPolicyChange(policy.copy(avoidAmbiguous = it)) },
                )
            }
        }
    }
}

@Composable
private fun LengthSlider(
    label: String,
    value: Int,
    range: IntRange,
    onChange: (Int) -> Unit,
) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(label, style = MaterialTheme.typography.labelLarge)
            Text(
                text = value.toString(),
                style = MaterialTheme.typography.labelLarge,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        Slider(
            value = value.toFloat(),
            onValueChange = { onChange(it.toInt()) },
            valueRange = range.first.toFloat()..range.last.toFloat(),
            steps = (range.last - range.first - 1).coerceAtLeast(0),
        )
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

/**
 * 独立生成器界面。
 *
 * 与很多生成器不同，这里把**熵与破解耗时**直接摆在密码下面：
 * 用户能立刻看到「把长度从 12 调到 20」到底带来了什么，
 * 而不是只看到一个含糊的「强/弱」标签。
 */
@Composable
fun GeneratorScreen(
    policy: PasswordPolicy,
    password: String,
    errorMessage: String?,
    onPolicyChange: (PasswordPolicy) -> Unit,
    onRegenerate: () -> Unit,
    onUse: (String) -> Unit,
    onCopy: (String) -> Unit,
) {
    val bits = remember(policy) { PasswordEntropy.bitsOf(policy) }
    val crackTime = remember(bits) { PasswordEntropy.crackTimeEstimate(bits) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = password.ifEmpty { "—" },
                    style = MaterialTheme.typography.headlineSmall,
                    fontFamily = FontFamily.Monospace,
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
                Spacer(Modifier.height(12.dp))
                StrengthMeter(
                    bits = bits,
                    crackTime = stringResource(R.string.gen_crack_time, crackTimeText(crackTime)),
                )
            }
        }

        if (errorMessage != null) {
            Spacer(Modifier.height(8.dp))
            Text(
                text = errorMessage,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onRegenerate, modifier = Modifier.weight(1f)) {
                Icon(Icons.Default.Refresh, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.gen_regenerate))
            }
            Button(
                onClick = { onCopy(password) },
                enabled = password.isNotEmpty(),
                modifier = Modifier.weight(1f),
            ) {
                Text(stringResource(R.string.gen_copy))
            }
        }

        Spacer(Modifier.height(20.dp))
        Text(
            text = stringResource(R.string.gen_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.height(12.dp))
        PolicyEditor(policy = policy, onPolicyChange = onPolicyChange)

        Spacer(Modifier.height(20.dp))
        Button(
            onClick = { onUse(password) },
            enabled = password.isNotEmpty(),
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp),
        ) {
            Text(stringResource(R.string.gen_use))
        }
        Spacer(Modifier.height(24.dp))
    }
}
