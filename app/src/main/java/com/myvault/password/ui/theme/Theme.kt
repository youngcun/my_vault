package com.myvault.password.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

/**
 * 配色。
 *
 * 刻意**不使用**动态取色（Material You）作为默认行为：
 * 密码库应该在任何设备上看起来都一样，用户才能依靠外观一致性
 * 判断「我正在输入的是我的密码库，而不是某个仿冒界面」。
 * 这是对抗钓鱼/覆盖式攻击的一点微小但真实的收益。
 */
private val VaultGreen = Color(0xFF1F6F5C)
private val VaultGreenDark = Color(0xFF0E4A3C)
private val VaultGreenLight = Color(0xFFA8D5C8)
private val VaultTeal = Color(0xFF4A6572)
private val VaultTealLight = Color(0xFFD3E1E8)
private val VaultError = Color(0xFFB3261E)
private val VaultErrorLight = Color(0xFFF9DEDC)

private val LightColors = lightColorScheme(
    primary = VaultGreen,
    onPrimary = Color.White,
    primaryContainer = VaultGreenLight,
    onPrimaryContainer = VaultGreenDark,
    secondary = VaultTeal,
    onSecondary = Color.White,
    secondaryContainer = VaultTealLight,
    onSecondaryContainer = Color(0xFF16323D),
    background = Color(0xFFF7F9F8),
    onBackground = Color(0xFF191C1B),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF191C1B),
    surfaceVariant = Color(0xFFDBE5E1),
    onSurfaceVariant = Color(0xFF3F4946),
    error = VaultError,
    onError = Color.White,
    errorContainer = VaultErrorLight,
    onErrorContainer = Color(0xFF410E0B),
    outline = Color(0xFF6F7975),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF6FD8BC),
    onPrimary = Color(0xFF003829),
    primaryContainer = Color(0xFF005141),
    onPrimaryContainer = Color(0xFF8BF5D8),
    secondary = Color(0xFFB4CBD8),
    onSecondary = Color(0xFF1E343D),
    secondaryContainer = Color(0xFF354A54),
    onSecondaryContainer = Color(0xFFD0E6F3),
    background = Color(0xFF101614),
    onBackground = Color(0xFFE0E3E1),
    surface = Color(0xFF18211E),
    onSurface = Color(0xFFE0E3E1),
    surfaceVariant = Color(0xFF3F4946),
    onSurfaceVariant = Color(0xFFBFC9C5),
    error = Color(0xFFF2B8B5),
    onError = Color(0xFF601410),
    errorContainer = Color(0xFF8C1D18),
    onErrorContainer = Color(0xFFF9DEDC),
    outline = Color(0xFF899390),
)

/** 应用是否允许使用动态取色（默认关闭，见上方说明）。 */
const val ENABLE_DYNAMIC_COLOR = false

@Composable
fun MyVaultTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = ENABLE_DYNAMIC_COLOR,
    content: @Composable () -> Unit,
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }
    MaterialTheme(
        colorScheme = colorScheme,
        typography = MaterialTheme.typography,
        content = content,
    )
}
