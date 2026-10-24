package com.myvault.password.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.myvault.password.R
import com.myvault.password.domain.VaultEntry
import com.myvault.password.ui.components.LocalUserActivity
import com.myvault.password.ui.components.localizedDisplayTitle
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

/**
 * 主列表。
 *
 * 交互设计上的一个刻意选择：**点击条目进入详情/编辑，而不是直接复制密码**。
 * 很多密码管理器把「点击即复制」做成默认行为，这会让「误触复制 → 密码进入
 * 剪贴板 → 被其他应用读取」变成常态。这里把复制放进明确的菜单项。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultListScreen(
    entries: List<VaultEntry>,
    query: String,
    message: String?,
    brokenEntryIds: List<String>,
    onQueryChange: (String) -> Unit,
    onOpenEntry: (VaultEntry) -> Unit,
    onAddEntry: () -> Unit,
    onToggleFavorite: (VaultEntry) -> Unit,
    onDeleteEntry: (VaultEntry) -> Unit,
    onCopy: (VaultEntry, String, Boolean) -> Unit,
    onCleanupBrokenEntries: () -> Unit,
    onOpenSettings: () -> Unit,
    /** 把一条凭据显示成二维码（用于导出到另一台设备）。 */
    onShowQr: (VaultEntry) -> Unit,
    onLock: () -> Unit,
    onMessageShown: () -> Unit,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    var pendingDelete by remember { mutableStateOf<VaultEntry?>(null) }
    var confirmBrokenCleanup by remember { mutableStateOf(false) }

    // 搜索框里的输入不产生指针事件（软键盘走 InputConnection），必须显式上报 ——
    // 详见 LocalUserActivity。
    val reportUserActivity = LocalUserActivity.current

    // 一次性提示的处理顺序很关键，它修掉了一个真实缺陷：
    //
    // 早先是 `showSnackbar(message); onMessageShown()` 连着写在同一个
    // LaunchedEffect 里。而 showSnackbar 会**挂起数秒直到提示从屏幕上消失**，
    // 于是「消费消息」这一步要等好几秒才发生。如果用户在这几秒内切到设置页，
    // 本 composable 被销毁、协程被取消，消息就永远留在 ViewModel 里；
    // 再回到列表页时 LaunchedEffect 重新触发，「已删除」又冒出来一次 ——
    // 明明什么都没删，却像刚删过。
    //
    // 现在的三条规则：
    //  1. **先消费、后显示**。消费只是把状态字段置空，不挂起，因此离开页面后
    //     这条消息不可能被重放；
    //  2. 显示用一个**不受本 composable 生命周期约束**的作用域发起，
    //     避免「消费后 message 变成 null → key 变化 → 协程被取消 →
    //     提示刚出现就被掐掉」；
    //  3. 用局部变量记下已经消费过的消息文本，因此连续两次删除（文本相同）
    //     依然会各显示一次提示。
    val scope = rememberCoroutineScope()
    var consumedText by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(message) {
        val text = message ?: return@LaunchedEffect
        if (text == consumedText) return@LaunchedEffect
        consumedText = text
        onMessageShown()
        scope.launch { snackbarHostState.showSnackbar(text) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(stringResource(R.string.list_title))
                        Text(
                            text = stringResource(R.string.list_entry_count, entries.size),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    actionIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
                actions = {
                    // 添加条目放在最左（锁定按钮左侧）。
                    //
                    // 这里**刻意不隐藏**右下角的浮动按钮：两个入口各有它擅长的场景 ——
                    // 列表很长时拇指在屏幕下半部分，浮动按钮更就手；
                    // 而搜索/滚动之后想立刻新增，视线在顶部，顶部按钮更直接。
                    // 密码管理器的「添加」是高频动作，多一个入口不会造成困惑，
                    // 但少一个入口会。
                    IconButton(onClick = onAddEntry) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = stringResource(R.string.cd_add_entry),
                        )
                    }
                    IconButton(onClick = onLock) {
                        Icon(Icons.Default.Lock, contentDescription = stringResource(R.string.list_lock))
                    }
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Default.Settings, contentDescription = stringResource(R.string.cd_settings))
                    }
                },
            )
        },
        snackbarHost = {
            // 提示居中显示。
            //
            // Material 的默认位置贴在屏幕底部，会**压住右下角的「添加条目」浮动按钮**
            // 与最后一条记录 —— 而删除条目之后用户最可能做的就是继续看列表或添加新条目。
            // 居中既避开了这两个热区，也让这条短暂反馈更容易被看到。
            // （顶部按钮不受影响：提示只在高度方向居中，不会顶到应用栏上。）
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center,
            ) {
                SnackbarHost(snackbarHostState)
            }
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onAddEntry,
                icon = { Icon(Icons.Default.Add, contentDescription = null) },
                text = { Text(stringResource(R.string.list_add)) },
            )
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner),
        ) {
            // 损坏条目必须显式提示。
            // 它们被容错逻辑跳过（一条坏数据不该让整库打不开），
            // 但绝不能被静默吞掉 —— 否则「保存成功却读不回来」会看起来像什么都没发生。
            if (brokenEntryIds.isNotEmpty()) {
                BrokenEntriesBanner(
                    count = brokenEntryIds.size,
                    onCleanup = { confirmBrokenCleanup = true },
                )
            }

            OutlinedTextField(
                value = query,
                onValueChange = { reportUserActivity(); onQueryChange(it) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                placeholder = { Text(stringResource(R.string.list_search_hint)) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                singleLine = true,
                shape = MaterialTheme.shapes.medium,
            )

            if (entries.isEmpty()) {
                EmptyState(
                    title = stringResource(R.string.list_empty),
                    hint = stringResource(R.string.list_empty_hint),
                )
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(bottom = 96.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp),
                ) {
                    items(entries, key = { it.id }) { entry ->
                        EntryRow(
                            entry = entry,
                            onOpen = { onOpenEntry(entry) },
                            onToggleFavorite = { onToggleFavorite(entry) },
                            onDelete = { pendingDelete = entry },
                            onCopyUsername = { onCopy(entry, entry.username, false) },
                            onCopyPassword = { onCopy(entry, entry.password, true) },
                            onShowQr = { onShowQr(entry) },
                        )
                    }
                }
            }
        }
    }

    pendingDelete?.let { target ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.entry_delete)) },
            text = { Text(stringResource(R.string.entry_delete_confirm, localizedDisplayTitle(target))) },
            confirmButton = {
                TextButton(onClick = {
                    onDeleteEntry(target)
                    pendingDelete = null
                }) {
                    Text(stringResource(R.string.entry_delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.entry_cancel))
                }
            },
        )
    }

    if (confirmBrokenCleanup) {
        AlertDialog(
            onDismissRequest = { confirmBrokenCleanup = false },
            title = { Text(stringResource(R.string.broken_entries_confirm_title)) },
            text = {
                Text(stringResource(R.string.broken_entries_confirm_body, brokenEntryIds.size))
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmBrokenCleanup = false
                    onCleanupBrokenEntries()
                }) {
                    Text(
                        stringResource(R.string.broken_entries_cleanup),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmBrokenCleanup = false }) {
                    Text(stringResource(R.string.entry_cancel))
                }
            },
        )
    }
}

/**
 * 损坏条目提示条。
 *
 * 用 errorContainer 语义色，确保用户不会把它当成普通信息而忽略 ——
 * 这条提示意味着「你的库里有一部分数据已经读不出来了」。
 */
@Composable
private fun BrokenEntriesBanner(count: Int, onCleanup: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onErrorContainer,
                )
                Text(
                    text = stringResource(R.string.broken_entries_title, count),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            Text(
                text = stringResource(R.string.broken_entries_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.padding(top = 4.dp),
            )
            TextButton(onClick = onCleanup) {
                Text(stringResource(R.string.broken_entries_cleanup))
            }
        }
    }
}

/** 单行条目。 */
@Composable
private fun EntryRow(
    entry: VaultEntry,
    onOpen: () -> Unit,
    onToggleFavorite: () -> Unit,
    onDelete: () -> Unit,
    onCopyUsername: () -> Unit,
    onCopyPassword: () -> Unit,
    onShowQr: () -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen),
        color = MaterialTheme.colorScheme.surface,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // 标题按当前语言解析一次，头像首字母与标题共用同一个值，
            // 避免「头像显示 U、标题显示（未命名）」这类不一致。
            val displayTitle = localizedDisplayTitle(entry)

            // 首字母头像：不请求任何网络 favicon（本应用也没有网络权限）
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .clip(CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Surface(
                    color = avatarColor(displayTitle),
                    shape = CircleShape,
                    modifier = Modifier.size(42.dp),
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(
                            text = displayTitle.take(1).uppercase(),
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onPrimary,
                        )
                    }
                }
            }

            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    text = displayTitle,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val subtitle = entry.displaySubtitle
                if (subtitle.isNotBlank()) {
                    Text(
                        text = subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }

            IconButton(onClick = onToggleFavorite) {
                Icon(
                    imageVector = if (entry.favorite) Icons.Default.Star else Icons.Default.StarBorder,
                    contentDescription = stringResource(R.string.entry_favorite_toggle),
                    tint = if (entry.favorite) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.outline
                    },
                )
            }

            Box {
                IconButton(onClick = { menuOpen = true }) {
                    Icon(Icons.Default.MoreVert, contentDescription = null)
                }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.entry_copy_username)) },
                        leadingIcon = { Icon(Icons.Default.ContentCopy, contentDescription = null) },
                        onClick = { menuOpen = false; onCopyUsername() },
                        enabled = entry.username.isNotBlank(),
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.entry_copy_password)) },
                        leadingIcon = { Icon(Icons.Default.Key, contentDescription = null) },
                        onClick = { menuOpen = false; onCopyPassword() },
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.entry_favorite_toggle)) },
                        leadingIcon = {
                            Icon(
                                if (entry.favorite) Icons.Default.Star else Icons.Default.StarBorder,
                                contentDescription = null,
                            )
                        },
                        onClick = { menuOpen = false; onToggleFavorite() },
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.entry_show_qr)) },
                        leadingIcon = { Icon(Icons.Default.QrCode2, contentDescription = null) },
                        onClick = { menuOpen = false; onShowQr() },
                    )
                    DropdownMenuItem(
                        text = {
                            Text(
                                stringResource(R.string.entry_delete),
                                color = MaterialTheme.colorScheme.error,
                            )
                        },
                        leadingIcon = {
                            Icon(
                                Icons.Default.Delete,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.error,
                            )
                        },
                        onClick = { menuOpen = false; onDelete() },
                    )
                }
            }
        }
    }
}

@Composable
private fun EmptyState(title: String, hint: String) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Default.Key,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.outline,
            modifier = Modifier.size(56.dp),
        )
        Spacer(Modifier.height(12.dp))
        Text(text = title, style = MaterialTheme.typography.titleMedium)
        Text(
            text = hint,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 6.dp),
        )
    }
}

/** 从标题稳定地派生一个头像颜色，避免使用随机数导致列表刷新时颜色跳动。 */
private fun avatarColor(title: String): androidx.compose.ui.graphics.Color {
    val palette = listOf(
        androidx.compose.ui.graphics.Color(0xFF1F6F5C),
        androidx.compose.ui.graphics.Color(0xFF3A6EA5),
        androidx.compose.ui.graphics.Color(0xFF8C5A2B),
        androidx.compose.ui.graphics.Color(0xFF6A4C93),
        androidx.compose.ui.graphics.Color(0xFF2E7D32),
        androidx.compose.ui.graphics.Color(0xFF9C4237),
    )
    val hash = title.fold(0) { acc, c -> acc * 31 + c.code }
    return palette[Math.floorMod(hash, palette.size)]
}

/** 时间格式化（供详情页使用）。 */
internal fun formatTimestamp(millis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(millis))
