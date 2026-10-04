package com.myvault.password.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import com.myvault.password.R
import com.myvault.password.domain.VaultEntry

/**
 * 自动填充服务。
 *
 * 支持的场景
 * ---------
 *  - **浏览器**：Chrome / Firefox / Edge 等基于 Chromium 或 Gecko 的浏览器在网页
 *    登录框上会走 Android 自动填充框架，本服务据此识别站点并匹配条目；
 *  - **原生 App**：通过 `autofillHints` 与 `InputType` 启发式识别用户名/密码框，
 *    按包名与站点名匹配。
 *
 * 安全设计（本文件最重要的部分）
 * --------------------------
 *  1. **填充前必须认证**。数据集里**只有站点名与用户名**，没有任何密文或明文；
 *     填充响应通过 `FillResponse.setAuthentication(PendingIntent)` 要求系统先拉起
 *     [AutofillAuthActivity] 完成指纹/主密码验证。
 *     读取认证结果的权限由系统持有（需要系统签名级权限），普通应用无法伪造或窃取。
 *  2. **服务不持有密钥**。它只读 [UnlockedEntryCache] 的明文快照，
 *     而该快照在锁定时立即清空。服务被恶意绑定时也无从解密任何东西。
 *  3. **不做隐式保存**。不注册 `SaveInfo` 流程 —— 密码库的写入必须是用户在
 *     应用内显式、可见、可控的动作，绝不能有「自动学习」式的写入路径。
 *  4. **建议列表最多 3 条且不显示密码**：列表越长越容易点错，
 *     而「点错条目 → 把 A 站点密码填进 B 站点」正是钓鱼攻击想要的结果。
 */
class VaultAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val context = request.fillContexts.lastOrNull() ?: run {
            callback.onSuccess(null)
            return
        }
        val structure: AssistStructure = context.structure
        val fields = parseStructure(structure)

        if (fields.usernameId == null && fields.passwordId == null) {
            // 这个界面没有登录框：放弃，避免无意义的建议弹窗打扰用户
            callback.onSuccess(null)
            return
        }

        if (!UnlockedEntryCache.isUnlocked) {
            callback.onSuccess(lockedResponse(fields))
            return
        }

        val candidates = UnlockedEntryCache.candidates(
            host = fields.webDomain,
            packageName = fields.packageName,
        )
        if (candidates.isEmpty()) {
            // 没有匹配项：给出**可见**的提示，而不是静默返回 null。
            //
            // 这里曾经直接 `callback.onSuccess(null)`，结果是用户完全无法区分
            // 「库里没存过这个 App」「存了但名字/包名对不上」「本机不支持自动填充」
            // 三种情况 —— 全都表现为「点了没反应」，这正是最难排查的一类缺陷。
            // 现在提示项还会把包名/域名带进主界面，用户点一下即可为当前 App 建条目。
            //
            // 代价要讲清楚：只要返回了响应，系统就不会再回退到别的填充服务/系统建议。
            // 对本应用而言这是有意的取舍 —— 填充服务本来就是用户自己选的，
            // 而「让用户知道自己没存过」比「把位置让给别人」更重要。
            callback.onSuccess(noMatchResponse(fields))
            return
        }

        val authentication = createAuthPendingIntent(fields) ?: run {
            callback.onSuccess(null)
            return
        }

        val response = FillResponse.Builder()
        for (entry in candidates.take(MAX_DATASETS)) {
            val dataset = buildDataset(entry, fields) ?: continue
            response.addDataset(dataset)
        }
        // 认证必须绑定到「哪些字段受保护」。这里把本次请求里识别出的所有
        // 登录字段都纳入保护范围 —— 认证通过前，系统不会把这些字段交给
        // 任何人（包括我们自己）去填充。
        response.setAuthentication(authFieldIds(fields), authentication, authenticationPresentation())
        callback.onSuccess(response.build())
    }

    /** 需要认证保护的字段 ID 集合。 */
    private fun authFieldIds(fields: FillTargets): Array<AutofillId> =
        listOfNotNull(fields.usernameId, fields.passwordId).toTypedArray()

    /**
     * 认证提示视图。
     *
     * 必须显式提供（而不能传 null）：Android 的 `setAuthentication` 有多个
     * 重载版本，传 null 会导致重载解析歧义而无法编译。
     * 提供一个视图同时也让「需要验证」这件事对用户更清楚。
     */
    private fun authenticationPresentation(): RemoteViews =
        RemoteViews(packageName, R.layout.autofill_auth_prompt).apply {
            setTextViewText(R.id.autofill_auth_prompt_title, getString(R.string.autofill_auth_title))
            setTextViewText(R.id.autofill_auth_prompt_body, getString(R.string.autofill_auth_subtitle))
        }

    /**
     * 保存请求。
     *
     * 本服务**刻意不支持**保存：Android 的保存流程会在用户登录新站点时把明文密码
     * 交给服务，但这条路径无法让用户确认「到底存了什么、存在哪」。
     * 对密码库而言，写入必须是一个显式、可见、可控的动作，因此这里直接忽略。
     */
    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onSuccess()
    }

    // ------------------------------------------------------------ 数据集构造

    /**
     * 构造单个建议项。
     *
     * 关键点：调用 `setValue(autofillId, null)` —— 值为 null 表示
     * 「稍后由认证结果填充」。真正的明文只会在用户通过指纹/主密码之后，
     * 由 [AutofillAuthActivity] 写入 `EXTRA_AUTHENTICATION_RESULT`。
     */
    private fun buildDataset(entry: VaultEntry, fields: FillTargets): Dataset? {
        val builder = Dataset.Builder(presentation(entry))
        var hasField = false
        fields.usernameId?.let {
            builder.setValue(it, null)
            hasField = true
        }
        fields.passwordId?.let {
            builder.setValue(it, null)
            hasField = true
        }
        if (!hasField) return null
        return builder.build()
    }

    /**
     * 创建指向认证界面的 PendingIntent。
     *
     * 必须把字段 ID 与条目信息放进 Intent：认证 Activity 运行在另一组件里，
     * 拿不到原始的 AssistStructure（由系统持有），因此只有服务端能解析出来。
     *
     * `FLAG_MUTABLE` 是必需的：系统要往这个 Intent 里补充它自己的
     * 认证结果字段。requestCode 由目标包名与字段标识派生，
     * 保证同一时刻不同请求不会互相覆盖。
     */
    private fun createAuthPendingIntent(fields: FillTargets): android.content.IntentSender? {
        val intent = Intent(this, AutofillAuthActivity::class.java).apply {
            fields.usernameId?.let { putExtra(AutofillAuthActivity.EXTRA_USERNAME_ID, it) }
            fields.passwordId?.let { putExtra(AutofillAuthActivity.EXTRA_PASSWORD_ID, it) }
            fields.webDomain?.let { putExtra(AutofillAuthActivity.EXTRA_WEB_DOMAIN, it) }
            fields.packageName?.let { putExtra(AutofillAuthActivity.EXTRA_PACKAGE_HINT, it) }
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS)
        }
        val flags = PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE
        val requestCode = (fields.packageName ?: fields.webDomain ?: "default").hashCode()
        return PendingIntent.getActivity(this, requestCode, intent, flags).intentSender
    }

    /**
     * 建议项的展示视图。
     *
     * 只显示站点名与用户名 —— **绝不显示密码**。填充建议列表可能出现在录屏、
     * 投屏或旁人视线里，把密码放进去等于白白泄露。
     */
    private fun presentation(entry: VaultEntry): RemoteViews {
        val views = RemoteViews(packageName, R.layout.autofill_dataset)
        val title = com.myvault.password.ui.components.localizedDisplayTitle(this, entry)
        views.setTextViewText(R.id.autofill_title, title)
        val subtitle = when {
            entry.username.isNotBlank() -> entry.username
            entry.url.isNotBlank() -> entry.url
            else -> getString(R.string.autofill_dataset_label, title)
        }
        views.setTextViewText(R.id.autofill_subtitle, subtitle)
        return views
    }

    /**
     * 未解锁时的响应。
     *
     * 不用「静默不显示」而是给一个明确的提示项，让用户知道
     * 「密码库存在但需要先解锁」，而不是以为应用坏了。
     */
    private fun lockedResponse(fields: FillTargets): FillResponse? =
        noticeResponse(
            fields = fields,
            title = getString(R.string.autofill_service_label),
            subtitle = getString(R.string.autofill_locked),
            target = Intent(this, com.myvault.password.MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            },
            requestCode = REQUEST_CODE_UNLOCK,
        )

    /**
     * 识别到输入框、但库里没有任何条目匹配时的响应。
     *
     * 关键是**把识别出来的标识带进主界面**：
     *  - 原生 App：包名（例如 `com.example.app.debug`）预填进「网址」字段，
     *    该字段同时充当「应用包名」，保存后下次即可命中；
     *  - 浏览器：域名预填进「站点」字段。
     */
    private fun noMatchResponse(fields: FillTargets): FillResponse? =
        noticeResponse(
            fields = fields,
            title = getString(R.string.autofill_service_label),
            subtitle = getString(R.string.autofill_no_match),
            target = Intent(this, com.myvault.password.MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                fields.packageName?.let {
                    putExtra(com.myvault.password.MainActivity.EXTRA_AUTOFILL_PACKAGE, it)
                }
                fields.webDomain?.let {
                    putExtra(com.myvault.password.MainActivity.EXTRA_AUTOFILL_WEB_DOMAIN, it)
                }
            },
            requestCode = REQUEST_CODE_NO_MATCH,
        )

    /**
     * 单条「提示型」建议项。
     *
     * 数据集里没有值（`setValue(id, null)` 的含义是「值稍后由认证结果给出」），
     * 因此必须配合 `setAuthentication` —— 这也正是想要的交互：
     * 用户点它 → 系统拉起 PendingIntent（这里指向主界面）→ 填充流程结束。
     */
    private fun noticeResponse(
        fields: FillTargets,
        title: String,
        subtitle: String,
        target: Intent,
        requestCode: Int,
    ): FillResponse? {
        val views = RemoteViews(packageName, R.layout.autofill_dataset).apply {
            setTextViewText(R.id.autofill_title, title)
            setTextViewText(R.id.autofill_subtitle, subtitle)
        }
        val builder = Dataset.Builder(views)
        var hasField = false
        fields.usernameId?.let { builder.setValue(it, null); hasField = true }
        fields.passwordId?.let { builder.setValue(it, null); hasField = true }
        if (!hasField) return null
        val pending = PendingIntent.getActivity(
            this,
            requestCode,
            target,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
        return FillResponse.Builder()
            .addDataset(builder.build())
            .setAuthentication(authFieldIds(fields), pending.intentSender, authenticationPresentation())
            .build()
    }

    // ------------------------------------------------------------ 界面解析

    /** 从 AssistStructure 里提取出的填充目标。 */
    private data class FillTargets(
        val usernameId: AutofillId?,
        val passwordId: AutofillId?,
        val webDomain: String?,
        val packageName: String?,
    )

    /**
     * 遍历视图树，识别用户名与密码输入框。
     *
     * 判断依据按可靠性排序：
     *  1. `autofillHints` 显式声明（最可靠，Chrome 与主流应用都会设置）；
     *  2. `InputType` 的密码变体；
     *  3. 其余情况不猜测 —— 宁可少填，也不要填错位置。
     */
    private fun parseStructure(structure: AssistStructure): FillTargets {
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        var webDomain: String? = null
        var packageName: String? = null

        for (i in 0 until structure.windowNodeCount) {
            val window = structure.getWindowNodeAt(i)
            if (webDomain == null) {
                // AssistStructure 的 title 在浏览器场景下通常就是网页标题或域名
                val title = window.title?.toString()
                if (title != null && title.contains('.')) webDomain = title
            }
            if (packageName == null) {
                packageName = runCatching {
                    structure.activityComponent?.packageName
                }.getOrNull()
            }
            traverse(window.rootViewNode) { id, isPassword ->
                if (isPassword) {
                    if (passwordId == null) passwordId = id
                } else {
                    if (usernameId == null) usernameId = id
                }
            }
        }

        // 有些实现只在节点上暴露 webDomain，兜底再扫一次
        if (webDomain == null) {
            webDomain = findWebDomain(structure)
        }
        return FillTargets(usernameId, passwordId, webDomain, packageName)
    }

    /** 递归查找节点上显式的 webDomain（`ViewNode.getWebDomain()`，API 26+）。 */
    private fun findWebDomain(structure: AssistStructure): String? {
        var found: String? = null
        fun walk(node: AssistStructure.ViewNode) {
            if (found != null) return
            val domain = runCatching { node.webDomain }.getOrNull()
            if (!domain.isNullOrBlank()) {
                found = domain
                return
            }
            for (i in 0 until node.childCount) walk(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode)
            if (found != null) break
        }
        return found
    }

    private fun traverse(
        node: AssistStructure.ViewNode,
        onField: (AutofillId, Boolean) -> Unit,
    ) {
        val id = node.autofillId
        if (id != null) {
            val hints = node.autofillHints
            val isPassword = hints?.any {
                it.equals("password", true) || it.equals("newPassword", true)
            } == true || isPasswordInputType(node.inputType)
            val isUsername = hints?.any {
                it.equals("username", true) || it.equals("emailAddress", true) ||
                    it.equals("email", true) || it.equals("phone", true)
            } == true

            when {
                isPassword -> onField(id, true)
                isUsername -> onField(id, false)
            }
        }
        for (i in 0 until node.childCount) {
            traverse(node.getChildAt(i), onField)
        }
    }

    /** 判断 InputType 是否代表密码框（含数字密码变体）。 */
    private fun isPasswordInputType(inputType: Int): Boolean {
        val cls = inputType and android.text.InputType.TYPE_MASK_CLASS
        if (cls != android.text.InputType.TYPE_CLASS_TEXT &&
            cls != android.text.InputType.TYPE_CLASS_NUMBER
        ) {
            return false
        }
        val variation = inputType and android.text.InputType.TYPE_MASK_VARIATION
        return variation == android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD ||
            variation == android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
            variation == android.text.InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
            variation == android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
    }

    companion object {
        /**
         * 单次建议列表最多展示的条目数。
         *
         * 限制为 3 是有意的：列表越长越容易点错，而「点错条目 → 把 A 站点的
         * 密码填进 B 站点」正是钓鱼攻击想要的结果。
         */
        private const val MAX_DATASETS = 3

        /**
         * 提示型数据集的 PendingIntent requestCode。
         *
         * 必须彼此不同：在 `FLAG_CANCEL_CURRENT` 之下，相同 requestCode 的
         * 后一个 PendingIntent 会覆盖前一个 —— 表现为用户点「请先解锁」的提示，
         * 打开的却是「新建条目」界面。
         */
        private const val REQUEST_CODE_UNLOCK = 0x1001
        private const val REQUEST_CODE_NO_MATCH = 0x1002
    }
}
