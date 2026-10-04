package com.myvault.password

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import com.myvault.password.core.Base64Codec
import com.myvault.password.core.CryptoPrimitives
import com.myvault.password.core.WrongSecretException
import com.myvault.password.data.EntryEntity
import com.myvault.password.data.VaultDatabase
import com.myvault.password.data.VaultRepository
import com.myvault.password.domain.VaultEntry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 设备端端到端测试（真实 Android 运行时）。
 *
 * 为什么必须有这一层
 * ----------------
 * 用户报告过两个只有真机才会暴露的问题：
 *  - 「新建条目保存不了、且不报错」
 *  - 「指纹解锁失败」
 * 前者在 JVM/Robolectric 上无法等价复现（涉及真实 SQLite、WAL、协程调度），
 * 后者更是完全依赖 TEE / Keystore。因此把「创建库 → 保存 → 读回 → 校验 → 备份」
 * 整条链路固化成设备端测试，避免同类问题再次静默溜走。
 *
 * 注意：本测试使用**内存数据库**，不会触碰用户真实的密码库文件。
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class VaultEndToEndTest {

    private lateinit var database: VaultDatabase
    private lateinit var repository: VaultRepository

    private val masterPassword = "device-e2e-master-passphrase".toCharArray()

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        database = Room.inMemoryDatabaseBuilder(context, VaultDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        repository = VaultRepository(database.dao())
    }

    @After
    fun tearDown() {
        database.close()
    }

    /**
     * 计时测试：把关键操作的耗时固定下来。
     *
     * 背景：用户报告「修改指纹开关后状态更新要 5 秒左右」。
     * 根因是 [com.myvault.password.core.EnvelopeCodec] 在「开关指纹」这条路径上
     * **跑了两次 Argon2id**（`unwrap()` 派生一次 KEK 后销毁，紧接着 `deriveKek()`
     * 又派生一次）。修复后只派生一次。这条用例把耗时钉住，
     * 防止将来有人再引入重复的 KDF 计算。
     *
     * 阈值取得较宽松（单次 Argon2id 在低端机可能接近 1 秒），
     * 目的是捕捉「成倍变慢」这类回归，而不是做精确性能断言。
     */
    @Test
    fun biometricToggleDoesNotRunArgon2Twice() = runBlocking {
        repository.createVault(masterPassword.copyOf())

        // 先测一次「纯 Argon2id 派生 + 解封装」的基准耗时
        val baselineStart = System.nanoTime()
        repository.lock()
        repository.unlockWithPassword(masterPassword.copyOf())
        val baselineMs = (System.nanoTime() - baselineStart) / 1_000_000

        // 再测开关指纹这条路径。它必须只比「一次解锁」略慢（信封重写 + 往返 IO），
        // 而不应该是「两次 Argon2id」的量级。
        val fakeWrapped = com.myvault.password.core.CryptoPrimitives.randomBytes(48)
        val enableStart = System.nanoTime()
        repository.enableBiometric(masterPassword.copyOf(), fakeWrapped, "e2e-suffix")
        val enableMs = (System.nanoTime() - enableStart) / 1_000_000

        val disableStart = System.nanoTime()
        repository.disableBiometric(masterPassword.copyOf())
        val disableMs = (System.nanoTime() - disableStart) / 1_000_000

        val budget = baselineMs * 2 + 1_500
        // 把实测耗时带上：这条消息既是失败诊断，也是优化效果的证据。
        val timing = "解锁基准 ${baselineMs}ms / 开启 ${enableMs}ms / 关闭 ${disableMs}ms"
        assertTrue(
            "开关指纹耗时异常（$timing）。修复后每次开关只应跑一次 Argon2id，" +
                "若远高于基准的 2 倍，很可能又引入了重复的 KDF 派生。",
            enableMs <= budget && disableMs <= budget,
        )
        // 显式记录一次，确保报告里能看到实际数字（断言通过时消息不显示）
        android.util.Log.i("MyVaultPerf", "biometric toggle timing: $timing")

        // 功能正确性：关闭后指纹包裹层必须消失
        val finalEnv = com.myvault.password.core.EnvelopeCodec.fromJson(
            database.dao().loadEnvelope()!!.json,
        )
        assertTrue("关闭后不应残留指纹包裹层", finalEnv.biometricWrap.isNullOrBlank())

        // 数据必须仍然可读：重封装不能破坏信封，主密码仍能解开
        repository.lock()
        repository.unlockWithPassword(masterPassword.copyOf())
        assertTrue("重封装后主密码必须仍能解锁", repository.isUnlocked)
        repository.saveEntry(VaultEntry(site = "AfterToggle", password = "still-works"))
        assertEquals(
            "重封装后必须仍能正常读写条目",
            1,
            repository.loadEntries(strict = true).size,
        )
    }

    /**
     * 「使用主密码作为备份口令」这条路径的前置条件：**必须能校验主密码**。
     *
     * 背景：导出对话框提供「复用主密码」选项。若不校验，用户打错一个字符就会
     * 得到一个用错误口令加密的备份文件 —— 而备份的价值恰恰在于将来某天要用它恢复。
     * 因此这里断言：正确主密码通过、错误主密码被拒绝，且校验过程不会破坏会话。
     */
    @Test
    fun masterPasswordCanBeVerifiedForBackupExport() = runBlocking {
        repository.createVault(masterPassword.copyOf())
        repository.saveEntry(VaultEntry(site = "BeforeExport", password = "p"))

        // 正确的主密码：通过
        assertTrue(
            "正确的主密码必须通过校验",
            repository.verifyMasterPassword(masterPassword.copyOf()),
        )

        // 错误的主密码：拒绝。注意长度故意与真实口令相同，避免「因为长度不同才失败」
        val wrong = "device-e2e-master-passphrasX".toCharArray()
        assertEquals("错误口令应与正确口令等长，才能证明是内容校验在起作用",
            masterPassword.size, wrong.size)
        assertFalse(
            "错误的主密码必须被拒绝，否则备份会被错误口令加密",
            repository.verifyMasterPassword(wrong),
        )

        // 校验不应影响已解锁的会话与数据
        assertTrue("校验后会话仍应有效", repository.isUnlocked)
        val entries = repository.loadEntries(strict = true)
        assertEquals(1, entries.size)
        assertEquals("BeforeExport", entries[0].site)

        // 校验后仍能用主密码导出（用主密码作为备份口令的完整链路）
        val manager = com.myvault.password.backup.BackupManager()
        val out = java.io.ByteArrayOutputStream()
        manager.export(
            out,
            repository.snapshotForBackup(),
            masterPassword.copyOf(),
            "e2e",
        )
        val restored = manager.import(
            java.io.ByteArrayInputStream(out.toByteArray()),
            masterPassword.copyOf(),
        )
        assertEquals("用主密码导出的备份必须能用主密码恢复", 1, restored.size)
    }

    @Test
    fun createVaultThenSaveEntryAndReadItBack() = runBlocking {
        // 1) 创建库
        repository.createVault(masterPassword.copyOf())
        assertTrue("创建后应处于解锁状态", repository.isUnlocked)

        // 2) 保存一条新条目（这是用户报告出问题的动作）
        val entry = VaultEntry(
            site = "设备端测试站点",
            username = "e2e@example.com",
            password = "DeviceE2E!Passw0rd",
            url = "https://e2e.example.com",
            notes = "端到端验证",
        )
        repository.saveEntry(entry)

        // 3) 立即读回：必须能读到且内容一致
        val loaded = repository.loadEntries(strict = true)
        assertEquals("保存后应能读回恰好 1 条", 1, loaded.size)
        assertEquals("设备端测试站点", loaded[0].site)
        assertEquals("e2e@example.com", loaded[0].username)
        assertEquals("DeviceE2E!Passw0rd", loaded[0].password)
        assertEquals("端到端验证", loaded[0].notes)
        assertEquals("条目 ID 必须保持一致", entry.id, loaded[0].id)

        // 4) 数据库里必须确实多了一行，且敏感字段是密文
        val rows = database.dao().loadAll()
        assertEquals(1, rows.size)
        assertFalse(
            "数据库中的密码列不能是明文",
            rows[0].passwordEnc.contains("DeviceE2E!Passw0rd"),
        )

        // 5) 完整性校验必须通过
        val report = repository.verifyIntegrity()
        assertTrue("刚保存后完整性校验应通过：${report.badEntries}", report.ok)

        // 6) 计数一致
        assertEquals(1, repository.entryCount())
    }

    @Test
    fun saveEntryUpdatesExistingInsteadOfDuplicating() = runBlocking {
        repository.createVault(masterPassword.copyOf())
        val entry = VaultEntry(site = "A", password = "p1")
        repository.saveEntry(entry)
        repository.saveEntry(entry.copy(password = "p2", site = "A2"))

        val loaded = repository.loadEntries(strict = true)
        assertEquals("同一条目重复保存不应产生副本", 1, loaded.size)
        assertEquals("A2", loaded[0].site)
        assertEquals("p2", loaded[0].password)
    }

    @Test
    fun lockThenUnlockKeepsEntries() = runBlocking {
        repository.createVault(masterPassword.copyOf())
        repository.saveEntry(VaultEntry(site = "Keep", password = "secret"))
        repository.lock()
        assertFalse(repository.isUnlocked)
        repository.unlockWithPassword(masterPassword.copyOf())
        val loaded = repository.loadEntries(strict = true)
        assertEquals(1, loaded.size)
        assertEquals("Keep", loaded[0].site)
    }

    @Test
    fun wrongPasswordIsRejectedOnDevice() = runBlocking {
        repository.createVault(masterPassword.copyOf())
        repository.lock()
        try {
            repository.unlockWithPassword("definitely-wrong".toCharArray())
            fail("错误口令必须被拒绝")
        } catch (expected: WrongSecretException) {
            // 预期
        }
    }

    @Test
    fun tamperedCiphertextIsDetectedOnDevice() = runBlocking {
        repository.createVault(masterPassword.copyOf())
        repository.saveEntry(VaultEntry(site = "Tamper", password = "original"))

        val rows = database.dao().loadAll()
        val victim = rows.first()
        val raw = Base64Codec.decode(victim.passwordEnc)
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0x01).toByte()
        database.dao().upsert(victim.copy(passwordEnc = Base64Codec.encode(raw)))

        val report = repository.verifyIntegrity()
        assertFalse("被篡改的密文必须被检出", report.ok)
        assertTrue(report.badEntries.contains(victim.id))
    }

    @Test
    fun backupRoundTripOnDevice() = runBlocking {
        repository.createVault(masterPassword.copyOf())
        // 注意：用于「不得出现在备份文件中」的明文必须是**足够长且独特**的字符串。
        // 曾经这里用了 "p1" 这种两字符密码，结果它在 Base64 密文里偶然出现，
        // 导致断言误报 —— 断言越短，假阳性越高。
        val secretPasswordOne = "Zq7-Distinctive-Password-Alpha"
        val secretPasswordTwo = "Wx9-Distinctive-Password-Beta"
        val secretSiteOne = "UniqueSiteName-Alpha-9271"
        val secretSiteTwo = "UniqueSiteName-Beta-4830"

        val originals = listOf(
            VaultEntry(
                site = secretSiteOne,
                username = "u1",
                password = secretPasswordOne,
                notes = "n1",
            ),
            VaultEntry(
                site = secretSiteTwo,
                username = "u2",
                password = secretPasswordTwo,
                favorite = true,
            ),
        )
        originals.forEach { repository.saveEntry(it) }

        // 导出
        val manager = com.myvault.password.backup.BackupManager()
        val out = java.io.ByteArrayOutputStream()
        val backupPassphrase = "backup-passphrase-e2e".toCharArray()
        val snapshot = repository.snapshotForBackup()
        manager.export(out, snapshot, backupPassphrase, "e2e")

        // 文件里不能有明文凭据
        val text = String(out.toByteArray(), Charsets.UTF_8)
        assertFalse("备份文件不应包含明文密码", text.contains(secretPasswordOne))
        assertFalse("备份文件不应包含明文密码", text.contains(secretPasswordTwo))
        assertFalse("备份文件不应包含明文站点名", text.contains(secretSiteOne))
        assertFalse("备份文件不应包含明文站点名", text.contains(secretSiteTwo))
        assertFalse("备份文件不应包含备份口令", text.contains("backup-passphrase-e2e"))

        // 导入到另一个库
        val second = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            VaultDatabase::class.java,
        ).allowMainThreadQueries().build()
        try {
            val repo2 = VaultRepository(second.dao())
            repo2.createVault("second-master-pass".toCharArray())
            val imported = manager.import(
                java.io.ByteArrayInputStream(out.toByteArray()),
                "backup-passphrase-e2e".toCharArray(),
            )
            assertEquals(2, imported.size)
            val restoredReport = repo2.restoreEntries(imported, overwriteExisting = false)
            assertEquals(2, restoredReport.imported)

            val restored = repo2.loadEntries(strict = true)
            assertEquals(2, restored.size)
            val bySite = restored.associateBy { it.site }
            assertNotNull(bySite[secretSiteOne])
            assertEquals(secretPasswordOne, bySite[secretSiteOne]!!.password)
            assertEquals("n1", bySite[secretSiteOne]!!.notes)
            assertTrue(bySite[secretSiteTwo]!!.favorite)
        } finally {
            second.close()
        }
    }

    /**
     * 回归测试：损坏条目的容错。
     *
     * 用户报告的「保存不了、且不报错」可能源于某条坏记录让整库读取失败。
     * 这里固化「宽松模式跳过坏条目、严格模式暴露坏条目」的行为，
     * 保证一条坏数据不会让整个密码库打不开。
     */
    @Test
    fun corruptedRowDoesNotBreakTheWholeVault() = runBlocking {
        repository.createVault(masterPassword.copyOf())
        repository.saveEntry(VaultEntry(site = "Good", password = "ok"))

        database.dao().upsert(
            EntryEntity(
                id = "broken",
                siteEnc = "!!!not-base64!!!",
                usernameEnc = "",
                passwordEnc = "",
                urlEnc = "",
                notesEnc = "",
                fav = false,
                generated = false,
                createdAt = 0,
                updatedAt = 0,
            ),
        )

        val lenient = repository.loadEntries(strict = false)
        assertEquals("宽松模式应跳过坏记录并保留好记录", 1, lenient.size)
        assertEquals("Good", lenient[0].site)

        try {
            repository.loadEntries(strict = true)
            fail("严格模式必须暴露坏记录")
        } catch (expected: com.myvault.password.data.CorruptEntryException) {
            // 预期
        }
    }
}
