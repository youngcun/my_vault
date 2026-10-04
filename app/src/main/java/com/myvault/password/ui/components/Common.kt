package com.myvault.password.ui.components

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.myvault.password.R
import com.myvault.password.core.PasswordEntropy
import com.myvault.password.core.PolicyError
import com.myvault.password.domain.VaultEntry

/**
 * 强度条。
 *
 * 这里展示的强度来自 [PasswordEntropy] 的**解析计算**，而不是对字符种类的
 * 粗略加分。区分很重要：前者可以解释「为什么是这个强度」，
 * 后者会让 "Password1!" 也显示成「强」。
 */
@Composable
fun StrengthMeter(
    bits: Double,
    modifier: Modifier = Modifier,
    crackTime: String? = null,
    showBits: Boolean = true,
) {
    val strength = PasswordEntropy.strengthOf(bits)
    val (color, label) = strengthVisual(strength)
    val fraction = (bits / 100.0).coerceIn(0.03, 1.0).toFloat()

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelLarge,
                color = color,
            )
            if (showBits) {
                Text(
                    text = "≈ %.1f bit".format(bits),
                    style = MaterialTheme.typography.labelMedium,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        LinearProgressIndicator(
            progress = { fraction },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 6.dp)
                .height(6.dp)
                .clip(RoundedCornerShape(3.dp)),
            color = color,
            trackColor = MaterialTheme.colorScheme.surfaceVariant,
        )
        if (crackTime != null) {
            Text(
                text = crackTime,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

/** 强度 → 颜色 / 文案。抽出来便于在别处复用同一套语义。 */
@Composable
fun strengthVisual(strength: PasswordEntropy.Strength): Pair<Color, String> {    val label = stringResource(
        when (strength) {
            PasswordEntropy.Strength.VERY_WEAK -> R.string.strength_very_weak
            PasswordEntropy.Strength.WEAK -> R.string.strength_weak
            PasswordEntropy.Strength.FAIR -> R.string.strength_fair
            PasswordEntropy.Strength.STRONG -> R.string.strength_strong
            PasswordEntropy.Strength.EXCELLENT -> R.string.strength_excellent
        },
    )
    val color = when (strength) {
        PasswordEntropy.Strength.VERY_WEAK -> MaterialTheme.colorScheme.error
        PasswordEntropy.Strength.WEAK -> MaterialTheme.colorScheme.error
        PasswordEntropy.Strength.FAIR -> Color(0xFFB26A00)
        PasswordEntropy.Strength.STRONG -> Color(0xFF2E7D32)
        PasswordEntropy.Strength.EXCELLENT -> Color(0xFF1F6F5C)
    }
    return color to label
}

/**
 * 条目在界面上的标题。
 *
 * [com.myvault.password.domain.VaultEntry.displayTitle] 是**领域层**的属性，
 * 那里的「（未命名）」是中文硬编码 —— 领域层没有 Context，且要被纯 JVM 测试
 * 直接使用，因此不能在那里做本地化。
 *
 * 界面上一律走这个函数：它在站点与用户名都为空时用当前语言的占位文案。
 * 注意**操作日志仍然使用领域层的 displayTitle**：日志是已落盘的记录，
 * 语言无关的数据比「看起来是当前语言」更重要。
 */
@Composable
fun localizedDisplayTitle(entry: VaultEntry): String =
    when {
        entry.site.isNotBlank() -> entry.site
        entry.username.isNotBlank() -> entry.username
        else -> stringResource(R.string.entry_display_title)
    }

/**
 * 与 [localizedDisplayTitle] 相同，但用于**非 Compose 上下文**
 * （自动填充服务、RemoteViews 数据集、认证 Activity）。
 *
 * 两条路径必须给出一样的标题，否则「建议列表里显示的名字」与
 * 「填充时确认框里的名字」会不一致 —— 而那正是用户用来核对
 * 「我要填的是不是这个站点」的依据。
 */
fun localizedDisplayTitle(context: Context, entry: VaultEntry): String =
    when {
        entry.site.isNotBlank() -> entry.site
        entry.username.isNotBlank() -> entry.username
        else -> context.getString(R.string.entry_display_title)
    }

/**
 * 生成器策略不可行的原因 → 当前语言的文案。
 *
 * `PasswordGenerator.PolicyError` 只描述「是哪一类问题、涉及哪些数字」，
 * 措辞在这里决定 —— 因此切换语言后，提示会跟着变，不会残留旧语言。
 */
@Composable
fun policyErrorText(error: PolicyError): String = when (error) {
    PolicyError.NoCharacterClass -> stringResource(R.string.gen_error_no_char_class)
}

/**
 * 爆破耗时 → 当前语言的文案。
 *
 * [PasswordEntropy.CrackTime.readable] 是**中文**硬编码（那一层没有 Context，
 * 要被纯 JVM 测试覆盖）。界面若直接用它，英文界面就会露出中文，
 * 因此这里按「刻度 + 数值」重新组装，语言由系统资源决定。
 */
@Composable
fun crackTimeText(crackTime: PasswordEntropy.CrackTime): String {
    val approx = crackTime.approx
    // 「远超宇宙年龄」是一个结论而不是一个数值，因此不加单位数字。
    if (approx == PasswordEntropy.Approx.BEYOND_UNIVERSE) {
        return stringResource(R.string.time_beyond_universe)
    }
    if (approx == PasswordEntropy.Approx.INSTANT) {
        return stringResource(R.string.time_instant)
    }
    val magnitude = "%.0f".format(approx.valueIn(crackTime.seconds))
    val unitRes = when (approx) {
        PasswordEntropy.Approx.SECONDS -> R.string.time_seconds
        PasswordEntropy.Approx.MINUTES -> R.string.time_minutes
        PasswordEntropy.Approx.HOURS -> R.string.time_hours
        PasswordEntropy.Approx.DAYS -> R.string.time_days
        PasswordEntropy.Approx.YEARS -> R.string.time_years
        PasswordEntropy.Approx.MILLENNIA -> R.string.time_millennia
        // 上面两个分支已提前 return，这里只为让 when 完备。
        PasswordEntropy.Approx.BEYOND_UNIVERSE,
        PasswordEntropy.Approx.INSTANT,
        -> R.string.time_instant
    }
    return stringResource(unitRes, magnitude)
}

/** 等宽字体展示密码/密钥，便于人工逐字符核对。 */
@Composable
fun MonoText(
    text: String,
    modifier: Modifier = Modifier,
    style: androidx.compose.ui.text.TextStyle = MaterialTheme.typography.bodyLarge,
) {
    Text(text = text, modifier = modifier, fontFamily = FontFamily.Monospace, style = style)
}

/**
 * 安全提示卡：用于「危险操作」「重要提醒」。
 * 语义色统一走 errorContainer，让用户一眼看出这不是普通信息。
 */
@Composable
fun WarningCard(
    title: String,
    body: String,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.errorContainer,
        shape = RoundedCornerShape(12.dp),
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Text(
                text = body,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

/** 通用信息卡（中性色）。 */
@Composable
fun InfoCard(
    title: String,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = RoundedCornerShape(12.dp),
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Column(Modifier.padding(top = 6.dp)) { content() }
        }
    }
}
