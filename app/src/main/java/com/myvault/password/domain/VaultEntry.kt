package com.myvault.password.domain

import java.util.UUID

/**
 * 凭据条目（解密后的内存形态）。
 *
 * 这个类**只应存在于已解锁会话的内存中**。它没有实现 Serializable、
 * 没有 toString 覆写密码字段，也不应被写入任何日志 —— 防止凭据被
 * 意外序列化到磁盘或打印到 logcat。
 */
data class VaultEntry(
    val id: String = UUID.randomUUID().toString(),
    val site: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val notes: String = "",
    val favorite: Boolean = false,
    /** 密码是否由本应用的生成器产生（用于在界面上提示密码来源）。 */
    val generated: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
) {
    /** 列表展示用的标题：站点为空时回退到用户名，再回退到占位符。 */
    val displayTitle: String
        get() = site.ifBlank { username.ifBlank { "（未命名）" } }

    /** 列表展示用的副标题。 */
    val displaySubtitle: String
        get() = when {
            site.isNotBlank() && username.isNotBlank() -> username
            url.isNotBlank() -> url
            notes.isNotBlank() -> notes.lineSequence().first().take(60)
            else -> ""
        }

    /**
     * 用于搜索的匹配判断。
     *
     * 刻意**不匹配密码字段** —— 否则搜索框会变成「密码内容探测工具」，
     * 而且用户输入的搜索词可能被输入法记录。
     */
    fun matches(query: String): Boolean {
        if (query.isBlank()) return true
        val q = query.trim().lowercase()
        return site.lowercase().contains(q) ||
            username.lowercase().contains(q) ||
            url.lowercase().contains(q) ||
            notes.lowercase().contains(q)
    }

    /**
     * 自动填充匹配度评分（0 表示不匹配）。
     *
     * 为什么需要评分而不是简单相等：用户在浏览器登录 `accounts.google.com`
     * 时，库里存的可能是 `google.com`；调用方 App 的包名可能是 `com.foo.app`
     * 而库里存的是「Foo」。
     *
     * 原生 App 场景（这是本条规则存在的真正原因）
     * --------------------------------------------
     * 浏览器会给出域名，**原生 App 只给出包名**，没有域名可用。因此：
     *
     *  1. 「网址」字段同时当作「网址或应用包名」使用 —— 填
     *     `com.example.app` 必须能命中 `com.example.app.debug`；
     *  2. 只看包名**最后一段**是不够的：debug 构建的末段常常就是 `debug`，
     *     等于没有信息（曾导致「存了密码却永远填不上」）；
     *  3. `com` / `android` / `app` / `debug` 这类通用段不参与匹配，
     *     否则任何条目都能和任何 App 产生弱关联；
     *  4. **只在没有域名可用时**才用包名匹配。网页上下文（浏览器、内嵌 WebView）
     *     里框架给出的包名是**宿主浏览器**的包名（`com.android.chrome`），
     *     它和用户要登录的网站毫无关系 —— 拿它匹配，一条「Chrome 应用」的条目
     *     会在所有网页上命中，正好制造「把 A 的密码填进 B」的事故。
     */
    fun matchScore(candidateHost: String?, candidatePackage: String?): Int {
        var score = 0
        val host = candidateHost?.lowercase()?.removePrefix("www.")?.trim()
        val pkg = candidatePackage?.lowercase()?.trim()

        if (!host.isNullOrBlank()) {
            val siteHost = normalizeHost(url).ifBlank { site.lowercase() }
            if (siteHost == host) {
                score += 100
            } else if (siteHost.isNotBlank() && (host.endsWith(".$siteHost") || siteHost.endsWith(".$host"))) {
                // 子域匹配：accounts.google.com ↔ google.com
                score += 70
            } else if (siteHost.contains(host) || host.contains(siteHost)) {
                score += 40
            }
        }

        // 有域名 = 网页上下文，包名是浏览器的包名，不能参与匹配（见上文第 4 条）
        if (host.isNullOrBlank() && !pkg.isNullOrBlank()) {
            val pkgKey = compact(pkg)
            // 网址栏里可能写的是包名，也可能是真实网址；两种都要能比对
            val urlKey = compact(url)
            val siteKey = compact(site)
            val tail = pkg.substringAfterLast('.')

            // 刻意写成阶梯（而不是把各档分值相加）：
            // 相加会让「某档弱命中」叠加成看起来很强的分数，用户无法预期
            // 哪一条会跳出来。阶梯保证「证据越强，分数越高，且只取最强的那一条」。
            score += when {
                // 1) 完全一致：最强的证据
                (urlKey.isNotBlank() && urlKey == pkgKey) ||
                    (siteKey.isNotBlank() && siteKey == pkgKey) -> 90

                // 2) 互相包含：com.example.app ⊂ com.example.app.debug
                //    要求含「.」是为了避免把普通网址前缀误判成包名
                listOf(urlKey, siteKey).any { key ->
                    key.length >= 6 && key.contains('.') &&
                        (key.contains(pkgKey) || pkgKey.contains(key))
                } -> 80

                // 3) 包名中的有效段（com.tencent.mm → tencent / mm）出现在站点名或网址里
                meaningfulSegments(pkg).any { seg ->
                    seg == siteKey ||
                        (siteKey.length >= 3 && siteKey.contains(seg)) ||
                        (urlKey.length >= 3 && urlKey.contains(seg))
                } -> 40

                // 4) 保底启发式：站点名包含包名末段（末段为通用词时跳过）
                !isGenericSegment(tail) && tail.length >= 3 && siteKey.contains(tail) -> 30

                // 5) 站点名本身就是通用词（app / debug / com）时不参与，
                //    否则「任意条目都可能匹配任意 App」
                siteKey.length >= 3 && !isGenericSegment(siteKey) && pkgKey.contains(siteKey) -> 20

                else -> 0
            }
        }
        return score
    }

    /** 去掉空白、下划线与连字符，便于「网址 vs 包名」这类不同写法的比较。 */
    private fun compact(raw: String): String =
        raw.trim().lowercase().replace(Regex("[\\s_\\-]"), "")

    /** 包名里真正有信息量的段（剔除通用段与过短的段）。 */
    private fun meaningfulSegments(pkg: String): List<String> =
        pkg.split('.').filter { it.length >= 3 && !isGenericSegment(it) }

    private fun isGenericSegment(segment: String): Boolean = segment in GENERIC_SEGMENTS

    private fun normalizeHost(rawUrl: String): String {
        if (rawUrl.isBlank()) return ""
        var s = rawUrl.trim().lowercase()
        s = s.removePrefix("https://").removePrefix("http://")
        s = s.substringBefore('/').substringBefore('?').substringBefore('#')
        s = s.substringAfter('@')            // 去掉 user@ 前缀
        s = s.substringBefore(':')           // 去掉端口
        return s.removePrefix("www.")
    }

    companion object {
        /**
         * 包名中不携带应用身份的通用段。
         *
         * 这些词几乎出现在每一个包名里（`com`、`android`），或者只描述构建类型
         * 与设备形态（`debug`、`release`、`hd`）。让它们参与匹配的后果是
         * 「任意条目都可能匹配任意 App」，比「匹配不上」更糟 ——
         * 把 A 站点的密码填进 B 应用正是钓鱼想要的结果。
         */
        private val GENERIC_SEGMENTS = setOf(
            "com", "cn", "net", "org", "io", "gov", "edu",
            "android", "app", "apps", "application",
            "mobile", "client", "phone", "pad", "tablet", "tv", "hd",
            "debug", "release", "beta", "alpha", "dev", "devenv", "test", "tests",
            "testing", "sandbox", "staging", "prod", "free", "pro", "plus", "lite",
        )

        /** 空条目模板，用于「新建」。 */
        fun empty(): VaultEntry = VaultEntry()
    }
}
