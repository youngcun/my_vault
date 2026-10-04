package com.myvault.password.ui.screens

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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.myvault.password.R
import com.myvault.password.operationlog.OpKind
import com.myvault.password.operationlog.formatLogDate
import com.myvault.password.operationlog.formatLogTime
import com.myvault.password.ui.OperationLogState
import com.myvault.password.ui.OperationLogViewItem
import com.myvault.password.ui.components.InfoCard

/**
 * 操作日志界面。
 *
 * 展示「最近 30 天的重要操作」：删除条目、修改主密码、修改站点/应用名称、
 * 导出与导入备份。这个界面的存在本身就是一种安全能力 ——
 * 如果有人在你的解锁会话里删掉了几条凭据，你应该能事后发现，
 * 而不是只看到「条目好像变少了」。
 *
 * 两条刻意的设计约束：
 *  1. **只读**。没有清空按钮：一份能被审计对象随手抹掉的记录没有价值。
 *  2. **不含凭据**。日志里只有操作类型、时间与名称。界面上的说明文字
 *     明确写出这一点，因为用户有权知道自己的什么数据被记了下来。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OperationLogScreen(
    state: OperationLogState,
    onBack: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.oplog_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    navigationIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = stringResource(R.string.common_back))
                    }
                },
            )
        },
    ) { inner ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner),
        ) {
            when {
                state.loading -> {
                    CircularProgressIndicator(Modifier.align(Alignment.Center))
                }

                state.items.isEmpty() -> {
                    EmptyLogState(retentionDays = state.retentionDays)
                }

                else -> {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(bottom = 24.dp),
                    ) {
                        item {
                            InfoCard(
                                title = stringResource(R.string.oplog_title),
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                            ) {
                                Text(
                                    text = stringResource(R.string.oplog_intro, state.retentionDays),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        // 用下标而不是在循环里 indexOf：后者会让列表渲染退化成
                        // 二次复杂度，日志一多就能感觉到卡顿。
                        itemsIndexed(state.items) { index, item ->
                            // 跨天时插一条日期分隔，让「这是今天的还是上周的」一目了然
                            val previous = state.items.getOrNull(index - 1)
                            if (previous == null || !sameDay(previous.at, item.at)) {
                                DayHeader(at = item.at)
                            }
                            LogRow(item)
                            HorizontalDivider(
                                color = MaterialTheme.colorScheme.surfaceVariant,
                                thickness = 1.dp,
                            )
                        }
                    }
                }
            }
        }
    }
}

/** 两条日志是否属于同一天（按本机时区）。 */
private fun sameDay(a: Long, b: Long): Boolean = formatLogDate(a) == formatLogDate(b)

@Composable
private fun DayHeader(at: Long) {
    Text(
        text = formatLogDate(at),
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp),
    )
}

/**
 * 单条日志。
 *
 * 图标与语义色按操作类别区分：删除类用 error 色（这是「数据消失」的操作），
 * 备份类用主色，改密/改名用中性色。用户扫一眼就能发现「那天有人删了东西」。
 */
@Composable
private fun LogRow(item: OperationLogViewItem) {
    val (icon, tint) = iconAndTint(item.kind)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Surface(
            color = tint.copy(alpha = 0.12f),
            shape = CircleShape,
            modifier = Modifier.size(36.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = tint,
                    modifier = Modifier.size(20.dp),
                )
            }
        }

        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = stringResource(item.titleRes),
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = formatLogTime(item.at),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            item.detailLines.forEach { line ->
                Text(
                    text = line,
                    style = MaterialTheme.typography.bodySmall,
                    // 重名用 error 色：它是这份日志里唯一需要用户「去做点什么」的信息
                    color = if (item.hasDuplicateNames && line.startsWith("⚠")) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
        }
    }
}

/** 操作类别 → 图标与强调色。 */
@Composable
private fun iconAndTint(kind: OpKind): Pair<ImageVector, androidx.compose.ui.graphics.Color> = when (kind) {
    OpKind.ENTRY_DELETED,
    OpKind.ENTRY_DELETED_IN_DETAIL,
    -> Icons.Default.Delete to MaterialTheme.colorScheme.error

    OpKind.MASTER_PASSWORD_CHANGED -> Icons.Default.Lock to MaterialTheme.colorScheme.primary

    OpKind.SITE_RENAMED -> Icons.Default.ContentCopy to MaterialTheme.colorScheme.tertiary
    OpKind.BACKUP_EXPORTED -> Icons.Default.FileDownload to MaterialTheme.colorScheme.primary
    OpKind.BACKUP_RESTORED -> Icons.Default.FileUpload to MaterialTheme.colorScheme.primary
}

/**
 * 空状态。
 *
 * 必须明确写出「记录范围」，而不是只显示一句「暂无记录」：
 * 用户看到空白时最可能的疑问是「是我没操作过，还是这个功能坏了」，
 * 把「哪些操作会被记录」写出来就能回答这个问题。
 */
@Composable
private fun EmptyLogState(retentionDays: Int) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Default.Warning,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.outline,
            modifier = Modifier.size(48.dp),
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.oplog_empty, retentionDays),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = stringResource(R.string.oplog_empty_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 6.dp),
        )
    }
}
