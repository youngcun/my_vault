package com.myvault.password.backup

import com.myvault.password.core.Base64Codec
import com.myvault.password.domain.VaultEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * 加密备份测试。
 *
 * 重点覆盖三类风险：
 *  1. **可用性**：导出的文件必须能被同一口令完整还原（否则备份等于没有）；
 *  2. **机密性**：文件里不能出现任何明文凭据（否则备份文件本身就是泄露源）；
 *  3. **完整性**：篡改头部参数或密文必须被拒绝，且要给出可区分的错误类型，
 *     让界面能告诉用户「是口令错了还是文件坏了」。
 */
class BackupManagerTest {

    private val manager = BackupManager()

    private fun sampleEntries(count: Int = 3): List<VaultEntry> = (1..count).map { i ->
        VaultEntry(
            id = "id-$i",
            // 注意：用于「不得出现在备份文件中」的明文必须足够长且独特。
            // 两三个字符的短串（例如 "p1"）会在 Base64 密文里偶然出现，
            // 导致断言假阳性 —— 这是一个真实踩过的坑。
            site = "DistinctiveSite-$i-9271",
            username = "distinctive-user-$i@example.com",
            password = "Zq7-Distinctive-Password-$i-4830",
            url = "https://distinctive-host-$i.example.com/login",
            notes = "DistinctiveNotes-$i-5162\n第二行",
            favorite = i % 2 == 0,
            generated = true,
            createdAt = 1_700_000_000_000L + i,
            updatedAt = 1_700_000_100_000L + i,
        )
    }

    private fun export(entries: List<VaultEntry>, passphrase: String): ByteArray {
        val out = ByteArrayOutputStream()
        manager.export(out, entries, passphrase.toCharArray(), "1.0.0-test")
        return out.toByteArray()
    }

    // ------------------------------------------------------------ 往返

    @Test
    fun `导出再导入可完整还原所有字段`() {
        val original = sampleEntries()
        val bytes = export(original, "backup-passphrase-123")
        val restored = manager.import(ByteArrayInputStream(bytes), "backup-passphrase-123".toCharArray())
        assertEquals(original.size, restored.size)
        original.zip(restored).forEach { (a, b) ->
            assertEquals(a.id, b.id)
            assertEquals(a.site, b.site)
            assertEquals(a.username, b.username)
            assertEquals(a.password, b.password)
            assertEquals(a.url, b.url)
            assertEquals(a.notes, b.notes)
            assertEquals(a.favorite, b.favorite)
            assertEquals(a.generated, b.generated)
            assertEquals(a.createdAt, b.createdAt)
            assertEquals(a.updatedAt, b.updatedAt)
        }
    }

    @Test
    fun `空库也能正常导出导入`() {
        val bytes = export(emptyList(), "passphrase-1234")
        val restored = manager.import(ByteArrayInputStream(bytes), "passphrase-1234".toCharArray())
        assertTrue(restored.isEmpty())
    }

    @Test
    fun `Unicode 与特殊字符不丢失`() {
        val entries = listOf(
            VaultEntry(
                id = "u1",
                site = "银行 🏦 \"引号\" \\反斜杠\\",
                username = "用户+tag@例子.中国",
                password = "a\"b'c`d\\e\u0000f\uD83D\uDE00",
                notes = "多行\n备注\r带特殊符号 <>&",
            ),
        )
        val bytes = export(entries, "口令-with-unicode-🔐")
        val restored = manager.import(ByteArrayInputStream(bytes), "口令-with-unicode-🔐".toCharArray())
        assertEquals(entries[0].site, restored[0].site)
        assertEquals(entries[0].username, restored[0].username)
        assertEquals(entries[0].password, restored[0].password)
        assertEquals(entries[0].notes, restored[0].notes)
    }

    // ------------------------------------------------------------ 机密性

    @Test
    fun `备份文件不包含任何明文凭据`() {
        val entries = sampleEntries()
        val bytes = export(entries, "backup-passphrase-123")
        val text = String(bytes, Charsets.UTF_8)

        // 头部元数据是明文（这是设计的一部分），但敏感字段绝不能出现
        assertTrue("文件头应包含格式标识", text.contains(BackupManager.MAGIC))
        for (entry in entries) {
            assertFalse("备份中出现了明文站点名", text.contains(entry.site))
            assertFalse("备份中出现了明文用户名", text.contains(entry.username))
            assertFalse("备份中出现了明文密码", text.contains(entry.password))
            assertFalse("备份中出现了明文网址", text.contains(entry.url))
            assertFalse("备份中出现了明文备注", text.contains(entry.notes))
        }
        // 备份口令本身当然也不能出现
        assertFalse(text.contains("backup-passphrase-123"))
    }

    @Test
    fun `每次导出的密文都不同（随机 salt 与 IV）`() {
        val entries = sampleEntries()
        val a = export(entries, "same-passphrase-123")
        val b = export(entries, "same-passphrase-123")
        assertFalse(
            "相同内容与相同口令两次导出必须产生不同字节，否则会泄露「内容未变」这一信息",
            a.contentEquals(b),
        )
    }

    // ------------------------------------------------------------ 完整性与错误区分

    @Test
    fun `错误口令被拒绝`() {
        val bytes = export(sampleEntries(), "correct-passphrase")
        try {
            manager.import(ByteArrayInputStream(bytes), "wrong-passphrase".toCharArray())
            fail("错误口令必须被拒绝")
        } catch (expected: BackupPassphraseException) {
            // 预期
        }
    }

    @Test
    fun `篡改 KDF 参数被 MAC 拒绝`() {
        val bytes = export(sampleEntries(), "passphrase-123456")
        val text = String(bytes, Charsets.UTF_8)
        // 从文件里读出真实的迭代次数再改小它（加快爆破的经典降级攻击）。
        // 不要写死期望值 —— 默认参数会随实测性能调整，
        // 写死会让这条测试因为「没找到要替换的字符串」而静默失效。
        val t = Regex("\"t\":\\s*(\\d+)").find(text)?.groupValues?.get(1)?.toInt()
            ?: fail("备份文件里应包含 Argon2 迭代次数").let { 0 }
        require(t > 1) { "迭代次数应大于 1，实际 $t" }

        val tampered = text.replaceFirst("\"t\": $t", "\"t\": ${t - 1}")
        assertFalse("测试前提：确实发生了替换", tampered == text)
        try {
            manager.import(ByteArrayInputStream(tampered.toByteArray()), "passphrase-123456".toCharArray())
            fail("KDF 参数被篡改必须被拒绝")
        } catch (expected: BackupPassphraseException) {
            // 预期
        }
    }

    @Test
    fun `篡改密文被拒绝`() {
        val bytes = export(sampleEntries(), "passphrase-123456")
        val env = BackupManager().let {
            // 直接构造一个密文被改动的文件
            val text = String(bytes, Charsets.UTF_8)
            val marker = "\"payload_enc\": \""
            val start = text.indexOf(marker) + marker.length
            val end = text.indexOf('"', start)
            val encoded = text.substring(start, end)
            val raw = Base64Codec.decode(encoded)
            raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0x01).toByte()
            text.replace(encoded, Base64Codec.encode(raw)).toByteArray()
        }
        try {
            manager.import(ByteArrayInputStream(env), "passphrase-123456".toCharArray())
            fail("密文被篡改必须被拒绝")
        } catch (expected: Exception) {
            assertTrue(
                "应报告为口令/篡改错误，实际 ${expected::class.simpleName}",
                expected is BackupPassphraseException,
            )
        }
    }

    @Test
    fun `非本应用的文件被报告为格式错误而不是口令错误`() {
        val garbage = "{\"hello\":\"world\"}".toByteArray()
        try {
            manager.import(ByteArrayInputStream(garbage), "any".toCharArray())
            fail("非法文件必须被拒绝")
        } catch (expected: BackupFormatException) {
            assertNotNull(expected.message)
        }
    }

    @Test
    fun `完全不是 JSON 的文件被拒绝`() {
        try {
            manager.importFromBytes("not json at all".toByteArray(), "any".toCharArray())
            fail("非法文件必须被拒绝")
        } catch (expected: BackupFormatException) {
            // 预期
        }
    }

    @Test
    fun `未来版本的文件被明确拒绝而不是误读`() {
        val bytes = export(sampleEntries(1), "passphrase-123456")
        val text = String(bytes, Charsets.UTF_8).replace("\"v\": 1", "\"v\": 99")
        try {
            manager.import(ByteArrayInputStream(text.toByteArray()), "passphrase-123456".toCharArray())
            fail("未来版本必须被拒绝")
        } catch (expected: BackupFormatException) {
            assertTrue(expected.message!!.contains("版本"))
        }
    }

    @Test
    fun `条目数与文件头不符时被拒绝`() {
        // 这一条防止「只删掉一部分条目」的隐形篡改
        val entries = sampleEntries(4)
        val bytes = export(entries, "passphrase-123456")
        val text = String(bytes, Charsets.UTF_8)
        val tampered = text.replace("\"entry_count\": 4", "\"entry_count\": 3")
        assertFalse(tampered == text)
        try {
            manager.importFromBytes(tampered.toByteArray(), "passphrase-123456".toCharArray())
            fail("条目数不一致必须被拒绝")
        } catch (expected: Exception) {
            // 头部被改动 → MAC 失败；无论哪种拒绝都是正确行为
            assertTrue(
                expected is BackupFormatException || expected is BackupPassphraseException,
            )
        }
    }

    @Test
    fun `超大文件被拒绝以防止内存耗尽`() {
        val huge = ByteArray((BackupManager.MAX_BACKUP_BYTES + 1).toInt())
        try {
            manager.importFromBytes(huge, "any".toCharArray())
            fail("超过大小上限的文件必须被拒绝")
        } catch (expected: BackupFormatException) {
            assertTrue(expected.message!!.contains("过大"))
        }
    }

    // ------------------------------------------------------------ 文件名

    @Test
    fun `建议文件名包含扩展名且可读`() {
        val name = BackupManager.suggestFileName()
        assertTrue(name.startsWith("myvault-backup-"))
        assertTrue(name.endsWith(".${BackupManager.FILE_EXTENSION}"))
    }

    /**
     * 文件名格式必须稳定且**可预期的自描述**。
     *
     * 备份文件一旦写出去可能几年不动，用户需要仅凭文件名就能判断
     * 它是什么、什么时候导出的。因此把格式在测试里钉死：
     *
     * `myvault-backup-yyyyMMdd-HHmmss.myvault`
     *
     * 同时验证：
     *  - 只有一个扩展名分隔点之后的后缀（不会被写成 `...myvault.json` 之类）；
     *  - 时间戳可被解析回一个合理的时间（防止时区/格式写错）；
     *  - 不同时刻生成的名字不同（否则连续导出会互相覆盖）。
     */
    @Test
    fun `建议文件名格式可解析且带时间戳`() {
        // 固定一个时间点，保证可重复
        val fixed = java.time.ZonedDateTime.of(2026, 10, 2, 13, 5, 9, 0, java.time.ZoneId.systemDefault())
            .toInstant().toEpochMilli()
        val name = BackupManager.suggestFileName(fixed)

        assertTrue(
            "文件名应形如 myvault-backup-yyyyMMdd-HHmmss.myvault，实际：$name",
            Regex("^myvault-backup-\\d{8}-\\d{6}\\.myvault$").matches(name),
        )

        // 时间戳部分必须能解析回原时间（精确到秒）
        val stamp = name.removePrefix("myvault-backup-").removeSuffix(".myvault")
        val parsed = java.time.LocalDateTime.parse(
            stamp,
            java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"),
        )
        val expected = java.time.LocalDateTime.ofInstant(
            java.time.Instant.ofEpochMilli(fixed),
            java.time.ZoneId.systemDefault(),
        )
        assertEquals(expected.withNano(0), parsed)

        // 相隔一秒的两个名字必须不同，避免覆盖
        assertFalse(
            "不同时刻的文件名不能相同",
            BackupManager.suggestFileName(fixed) == BackupManager.suggestFileName(fixed + 1000),
        )
    }

    /**
     * 备份文件的 MIME 类型不能是 `application/octet-stream`。
     *
     * 原因：备份文件本身是自包含 JSON，而部分文件管理器会按 MIME 猜测/改写扩展名，
     * `octet-stream` 容易让 `.myvault` 后缀被吞掉或改成 `.bin`，
     * 用户就拿到一个「看不出是什么」的文件。
     */
    @Test
    fun `导出使用的 MIME 类型不会干扰扩展名`() {
        assertEquals(
            "导出应使用 application/json（见 MainActivity.BACKUP_MIME_TYPE 的说明）",
            "application/json",
            com.myvault.password.MainActivity.BACKUP_MIME_TYPE,
        )
    }

    // ------------------------------------------------------------ 跨库一致性

    @Test
    fun `备份与密码库使用互不相同的密钥体系`() {
        // 备份文件里只有 salt 与 KDF 参数，没有主库的信封；
        // 因此即使备份口令 = 主密码，两处的派生结果也因为 salt 不同而不同。
        val bytesA = export(sampleEntries(1), "identical-passphrase")
        val bytesB = export(sampleEntries(1), "identical-passphrase")
        val saltOf = { b: ByteArray ->
            val t = String(b, Charsets.UTF_8)
            val m = "\"salt\": \""
            val s = t.indexOf(m) + m.length
            t.substring(s, t.indexOf('"', s))
        }
        assertFalse(
            "两次导出必须使用不同 salt，否则相同口令在不同文件中会派生出相同密钥",
            saltOf(bytesA) == saltOf(bytesB),
        )
    }
}
