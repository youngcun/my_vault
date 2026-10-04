package com.myvault.password.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 自动填充匹配规则的回归测试（纯 JVM，不依赖 Android）。
 *
 * 为什么这些用例必须存在：整套自动填充里最难排查的缺陷不是「填错」，
 * 而是「什么都不发生」——
 *
 *  - 曾经**只按包名最后一段**匹配站点名，于是 debug 构建
 *    （`com.example.app.debug` → 末段 `debug`）永远匹配不上，
 *    用户明明存了密码却什么都看不到；
 *  - 「网址」字段当时完全不参与包名匹配，用户把包名填进去也没用。
 *
 * 下面第 3、4、5 条用例就是钉住这两个缺陷的。
 */
class VaultEntryMatchScoreTest {

    // ------------------------------------------------------------ 浏览器场景

    @Test
    fun `浏览器域名精确匹配得分最高`() {
        val entry = VaultEntry(site = "GitHub", url = "https://github.com/login")
        assertEquals(100, entry.matchScore(candidateHost = "github.com", candidatePackage = null))
    }

    @Test
    fun `浏览器子域匹配`() {
        val entry = VaultEntry(site = "Google", url = "google.com")
        assertEquals(70, entry.matchScore(candidateHost = "accounts.google.com", candidatePackage = null))
    }

    @Test
    fun `网页上下文不使用宿主浏览器的包名匹配`() {
        // 「Chrome 应用」这一条把自己的包名写进了网址。
        // 如果在网页上下文里也拿包名去匹配，它会在**所有**网页上命中 ——
        // 那正是「把 A 的密码填进 B」的经典事故。
        val chromeEntry = VaultEntry(site = "Chrome", url = "com.android.chrome", password = "p")
        assertEquals(0, chromeEntry.matchScore(candidateHost = "example.com", candidatePackage = "com.android.chrome"))
        // 没有域名（即 Chrome 自己的原生界面）时才允许按包名匹配
        assertTrue(chromeEntry.matchScore(candidateHost = null, candidatePackage = "com.android.chrome") > 0)
    }

    // ------------------------------------------------------------ 原生 App 场景

    @Test
    fun `网址字段写成完整包名时命中`() {
        val entry = VaultEntry(site = "示例应用", url = "com.example.app.debug")
        assertEquals(90, entry.matchScore(candidateHost = null, candidatePackage = "com.example.app.debug"))
    }

    @Test
    fun `中文站点名加上层包名也能命中 debug 构建`() {
        // 本次真实故障：站点名与包名不一致，且包名末段是毫无信息量的 debug
        val entry = VaultEntry(site = "示例应用", url = "com.example.app")
        assertTrue(
            "上层包名必须能命中 debug 构建，否则用户存了密码也永远填不上",
            entry.matchScore(candidateHost = null, candidatePackage = "com.example.app.debug") >= 80,
        )
    }

    @Test
    fun `包名中的有效段与站点名匹配`() {
        val entry = VaultEntry(site = "example 示例应用", url = "")
        assertEquals(40, entry.matchScore(candidateHost = null, candidatePackage = "com.example.app.debug"))
    }

    @Test
    fun `站点名包含包名末段时弱匹配`() {
        val entry = VaultEntry(site = "Notes App", url = "")
        assertEquals(40, entry.matchScore(candidateHost = null, candidatePackage = "com.example.notes"))
    }

    @Test
    fun `站点名写成完整包名时命中`() {
        val entry = VaultEntry(site = "com.example.notes", url = "")
        assertEquals(80, entry.matchScore(candidateHost = null, candidatePackage = "com.example.notes.pro"))
    }

    @Test
    fun `站点名是包名的一部分时给最低分`() {
        val entry = VaultEntry(site = "abcde", url = "")
        assertEquals(20, entry.matchScore(candidateHost = null, candidatePackage = "com.abcdef.app"))
    }

    // ------------------------------------------------------------ 不该匹配的情形

    @Test
    fun `无关条目不得命中`() {
        val entry = VaultEntry(site = "网易云音乐", url = "", notes = "音乐账号")
        assertEquals(0, entry.matchScore(candidateHost = null, candidatePackage = "com.netease.cloudmusic"))
        assertEquals(0, entry.matchScore(candidateHost = "example.com", candidatePackage = null))
    }

    @Test
    fun `通用段不参与匹配`() {
        val entry = VaultEntry(site = "debug", url = "")
        assertEquals(0, entry.matchScore(candidateHost = null, candidatePackage = "com.example.app.debug"))
        val appEntry = VaultEntry(site = "app", url = "")
        assertEquals(0, appEntry.matchScore(candidateHost = null, candidatePackage = "com.example.app"))
    }

    @Test
    fun `两个标识都为空时不匹配`() {
        val entry = VaultEntry(site = "Anything", url = "example.com")
        assertEquals(0, entry.matchScore(candidateHost = null, candidatePackage = null))
        assertEquals(0, entry.matchScore(candidateHost = "", candidatePackage = "  "))
    }

    @Test
    fun `网页上下文的包名线索被忽略`() {
        // 浏览器请求同时带来域名与（浏览器的）包名时，只认域名 ——
        // 否则「把浏览器自己的包名当成网站标识」会污染评分
        val entry = VaultEntry(site = "Example", url = "example.com")
        assertEquals(100, entry.matchScore(candidateHost = "example.com", candidatePackage = "com.example.browser"))
    }
}
