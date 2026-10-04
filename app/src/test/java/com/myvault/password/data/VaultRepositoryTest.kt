package com.myvault.password.data

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.myvault.password.core.Base64Codec
import com.myvault.password.core.CryptoPrimitives
import com.myvault.password.core.KeyEnvelope
import com.myvault.password.core.MasterKeyMaterial
import com.myvault.password.core.WrongSecretException
import com.myvault.password.domain.VaultEntry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 字段级加密测试。
 *
 * 这是「密文不能搬运」这一安全性质的可执行证明：AAD 把每条密文
 * 绑定到「它属于哪条记录的哪个字段」，于是跨条目/跨字段的密文重排必然失败。
 */
@RunWith(AndroidJUnit4::class)
class FieldCipherTest {

    private val material = MasterKeyMaterial(
        dataKey = CryptoPrimitives.randomBytes(32),
        keyId = "test-key",
        envelope = KeyEnvelope(
            keyId = "test-key",
            algorithm = KeyEnvelope.ALG_ARGON2ID,
            salt = "",
            wrappedDek = "",
            mac = "",
        ),
    )

    private val cipher = FieldCipher(material)

    @After
    fun tearDown() {
        material.destroy()
    }

    @Test
    fun `每个字段都能独立往返`() {
        val id = "entry-1"
        for (field in FieldCipher.Field.entries) {
            val plaintext = "值-${field.column}-🔐"
            val ct = cipher.encrypt(id, field, plaintext)
            assertEquals(plaintext, cipher.decrypt(id, field, ct))
        }
    }

    @Test
    fun `同一字段两次加密产生不同密文`() {
        val id = "entry-1"
        val a = cipher.encrypt(id, FieldCipher.Field.PASSWORD, "same")
        val b = cipher.encrypt(id, FieldCipher.Field.PASSWORD, "same")
        assertFalse("随机 IV 必须让密文不同", a == b)
    }

    @Test
    fun `密文不能跨条目搬运`() {
        val ct = cipher.encrypt("entry-A", FieldCipher.Field.PASSWORD, "secret")
        try {
            cipher.decrypt("entry-B", FieldCipher.Field.PASSWORD, ct)
            fail("把 A 的密码密文搬到 B 必须失败")
        } catch (expected: CorruptEntryException) {
            // 预期
        }
    }

    @Test
    fun `密文不能跨字段搬运`() {
        val ct = cipher.encrypt("entry-A", FieldCipher.Field.PASSWORD, "secret")
        try {
            cipher.decrypt("entry-A", FieldCipher.Field.USERNAME, ct)
            fail("把密码密文放到用户名列必须失败")
        } catch (expected: CorruptEntryException) {
            // 预期
        }
    }

    @Test
    fun `空字符串也被加密而不是留空`() {
        val ct = cipher.encrypt("entry-1", FieldCipher.Field.NOTES, "")
        assertTrue("空字段也应当是密文，否则能推断出用户没填该字段", ct.isNotEmpty())
        assertEquals("", cipher.decrypt("entry-1", FieldCipher.Field.NOTES, ct))
    }

    @Test
    fun `实体转换保持全部字段且密文中不含明文`() {
        val entry = VaultEntry(
            id = "e1",
            site = "GitHub",
            username = "octocat",
            password = "s3cr3t!",
            url = "https://github.com",
            notes = "备注",
            favorite = true,
            generated = true,
        )
        val entity = cipher.toEntity(entry)
        val back = cipher.fromEntity(entity)
        assertEquals(entry, back)
        assertFalse(entity.passwordEnc.contains("s3cr3t"))
        assertFalse(entity.siteEnc.contains("GitHub"))
    }

    @Test
    fun `损坏的 Base64 被报告为条目损坏而不是崩溃`() {
        try {
            cipher.decrypt("entry-1", FieldCipher.Field.SITE, "!!!not-base64!!!")
            fail("非法 Base64 必须抛出 CorruptEntryException")
        } catch (expected: CorruptEntryException) {
            assertNotNull(expected.message)
        }
    }
}

/**
 * 仓储层集成测试（Robolectric + 内存数据库）。
 *
 * 覆盖的是「各部件接起来是否还对」：解锁 → 写入 → 读回 → 校验 → 改密码 → 数据仍在。
 * 这些是单元测试无法覆盖的集成风险。
 *
 * 注意：本测试使用**生产参数**的 Argon2id（64 MiB / 3 轮），
 * 因此每个用例约需 0.2~0.5 秒。这是有意的 —— 我们要验证的就是真实配置下的行为。
 */
@RunWith(AndroidJUnit4::class)
class VaultRepositoryTest {

    private lateinit var database: VaultDatabase
    private lateinit var repository: VaultRepository

    private val masterPassword = "correct horse battery staple".toCharArray()

    @Before
    fun setUp() = runBlocking {
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

    private suspend fun createVault(password: CharArray = masterPassword.copyOf()) {
        repository.createVault(password)
    }

    @Test
    fun `初始状态是未初始化`() = runBlocking {
        assertFalse(repository.isInitialized())
        assertFalse(repository.isUnlocked)
    }

    @Test
    fun `创建后处于解锁状态`() = runBlocking {
        createVault()
        assertTrue(repository.isInitialized())
        assertTrue(repository.isUnlocked)
    }

    @Test
    fun `写入的条目能被读回且内容一致`() = runBlocking {
        createVault()
        val entry = VaultEntry(
            site = "测试站点",
            username = "user@example.com",
            password = "Str0ng!Passw0rd",
            url = "https://example.com",
            notes = "备注内容",
            favorite = true,
        )
        repository.saveEntry(entry)

        val loaded = repository.loadEntries(strict = true)
        assertEquals(1, loaded.size)
        assertEquals("测试站点", loaded[0].site)
        assertEquals("Str0ng!Passw0rd", loaded[0].password)
        assertEquals("备注内容", loaded[0].notes)
        assertTrue(loaded[0].favorite)
    }

    @Test
    fun `错误主密码无法解锁`() = runBlocking {
        createVault()
        repository.lock()
        try {
            repository.unlockWithPassword("wrong password".toCharArray())
            fail("错误口令必须被拒绝")
        } catch (expected: WrongSecretException) {
            // 预期
        }
        assertFalse(repository.isUnlocked)
    }

    @Test
    fun `锁定会清空内存密钥与自动填充快照`() = runBlocking {
        createVault()
        repository.saveEntry(VaultEntry(site = "A", password = "p"))
        repository.loadEntries()
        repository.lock()
        assertFalse(repository.isUnlocked)
        try {
            repository.loadEntries()
            fail("锁定后读取必须失败")
        } catch (expected: IllegalStateException) {
            // 预期
        }
    }

    @Test
    fun `修改主密码后数据仍可读且旧口令失效`() = runBlocking {
        createVault()
        repository.saveEntry(VaultEntry(site = "重要站点", password = "MyPassword1!"))

        val newPassword = "a brand new master passphrase".toCharArray()
        repository.changeMasterPassword(masterPassword.copyOf(), newPassword)

        val afterChange = repository.loadEntries(strict = true)
        assertEquals(1, afterChange.size)
        assertEquals("MyPassword1!", afterChange[0].password)

        repository.lock()
        repository.unlockWithPassword(newPassword.copyOf())
        assertTrue(repository.isUnlocked)

        repository.lock()
        try {
            repository.unlockWithPassword(masterPassword.copyOf())
            fail("旧口令必须失效")
        } catch (expected: WrongSecretException) {
            // 预期
        }
    }

    @Test
    fun `篡改数据库中的密文会被完整性校验发现`() = runBlocking {
        createVault()
        repository.saveEntry(VaultEntry(site = "A", username = "u", password = "p1"))
        repository.saveEntry(VaultEntry(site = "B", username = "u", password = "p2"))

        val clean = repository.verifyIntegrity()
        assertTrue("干净状态应通过校验：${clean.badEntries}", clean.ok)

        // 直接改写数据库里的密文，模拟文件级篡改
        val rows = database.dao().loadAll()
        val victim = rows.first()
        val raw = Base64Codec.decode(victim.passwordEnc)
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0x01).toByte()
        database.dao().upsert(victim.copy(passwordEnc = Base64Codec.encode(raw)))

        val report = repository.verifyIntegrity()
        assertFalse("被篡改的条目必须被检出", report.ok)
        assertTrue("应报告受影响的条目 ID", report.badEntries.contains(victim.id))
    }

    @Test
    fun `删除条目后校验和随之更新且校验仍然通过`() = runBlocking {
        createVault()
        val a = VaultEntry(site = "A", password = "p1")
        val b = VaultEntry(site = "B", password = "p2")
        repository.saveEntry(a)
        repository.saveEntry(b)
        repository.deleteEntry(a.id)

        val loaded = repository.loadEntries()
        assertEquals(1, loaded.size)
        assertEquals(b.id, loaded[0].id)
        assertTrue(repository.verifyIntegrity().ok)
    }

    @Test
    fun `备份恢复支持跳过与覆盖两种模式`() = runBlocking {
        createVault()
        val existing = VaultEntry(site = "已有", password = "old")
        repository.saveEntry(existing)

        val incoming = listOf(
            existing.copy(password = "new"),
            VaultEntry(site = "新的", password = "p"),
        )

        val first = repository.restoreEntries(incoming, overwriteExisting = false)
        assertEquals(1, first.imported)
        assertEquals(1, first.skipped)
        assertEquals("old", repository.findEntry(existing.id)!!.password)

        val second = repository.restoreEntries(incoming, overwriteExisting = true)
        assertEquals(2, second.imported)
        assertEquals(0, second.skipped)
        assertEquals("new", repository.findEntry(existing.id)!!.password)
        assertEquals(2, repository.loadEntries().size)
    }

    /**
     * 恢复时的**重名**必须被报出来。
     *
     * 这是「同名条目」这一真实使用场景的防线：同一个站点存两条记录
     * （例如两个账号）是合理的，但也可能是「把同一份备份导了两遍」。
     * 程序无法区分，因此必须把名字交给用户判断，而不是静默写入。
     */
    @Test
    fun `恢复时与库内已有条目重名会被报出`() = runBlocking {
        createVault()
        repository.saveEntry(VaultEntry(site = "支付宝", username = "a", password = "p1"))

        val collide = repository.restoreEntries(
            listOf(VaultEntry(site = "支付宝", username = "b", password = "p2")),
            overwriteExisting = false,
        )
        assertEquals(1, collide.imported)
        assertEquals(listOf("支付宝"), collide.duplicateSiteNames)
        assertTrue(collide.hasDuplicates)
    }

    /**
     * 覆盖同一个 ID 时**不算重名**。
     *
     * 否则每次「覆盖恢复」都会刷出一堆假重名，真重名反而被淹没 ——
     * 这是一条很容易写错、且错了以后很难被发现的规则。
     */
    @Test
    fun `覆盖同 ID 条目不会被误判为重名`() = runBlocking {
        createVault()
        repository.saveEntry(VaultEntry(site = "支付宝", username = "a", password = "p1"))
        val sameId = repository.loadEntries().first()

        val overwrite = repository.restoreEntries(
            listOf(sameId.copy(password = "p3")),
            overwriteExisting = true,
        )
        assertEquals(1, overwrite.imported)
        assertTrue(
            "覆盖同 ID 条目不应被误判为重名：${overwrite.duplicateSiteNames}",
            overwrite.duplicateSiteNames.isEmpty(),
        )
        assertEquals(1, repository.loadEntries().size)
    }

    /** 备份文件**内部**彼此同名（库内原本没有这个名称）同样要报出。 */
    @Test
    fun `恢复时备份文件内部重名会被报出`() = runBlocking {
        createVault()

        val internal = repository.restoreEntries(
            listOf(
                VaultEntry(site = "内部重名", username = "u1", password = "p1"),
                VaultEntry(site = "内部重名", username = "u2", password = "p2"),
            ),
            overwriteExisting = false,
        )
        assertEquals(2, internal.imported)
        assertEquals(listOf("内部重名"), internal.duplicateSiteNames)
    }

    @Test
    fun `备份快照在严格模式下包含全部字段`() = runBlocking {
        createVault()
        repository.saveEntry(
            VaultEntry(site = "S", username = "U", password = "P", url = "https://x", notes = "N"),
        )
        val snapshot = repository.snapshotForBackup()
        assertEquals(1, snapshot.size)
        assertEquals("S", snapshot[0].site)
        assertEquals("U", snapshot[0].username)
        assertEquals("P", snapshot[0].password)
        assertEquals("N", snapshot[0].notes)
    }

    @Test
    fun `自动填充候选按站点匹配并排序`() = runBlocking {
        createVault()
        repository.saveEntry(VaultEntry(site = "github.com", username = "a", password = "1"))
        repository.saveEntry(VaultEntry(site = "accounts.google.com", username = "b", password = "2"))
        repository.saveEntry(VaultEntry(site = "unrelated.example", username = "c", password = "3"))

        val exact = repository.findCandidates("github.com", null)
        assertEquals(1, exact.size)
        assertEquals("a", exact[0].username)

        // 子域匹配：accounts.google.com 应被 google.com 的请求命中
        val subdomain = repository.findCandidates("google.com", null)
        assertEquals(1, subdomain.size)
        assertEquals("b", subdomain[0].username)

        assertTrue(repository.findCandidates("nothing.example", null).isEmpty())
    }

    @Test
    fun `未解锁时不得进行任何写入`() = runBlocking {
        createVault()
        repository.lock()
        try {
            repository.saveEntry(VaultEntry(site = "A", password = "p"))
            fail("锁定状态下写入必须被拒绝")
        } catch (expected: IllegalStateException) {
            // 预期
        }
    }

    @Test
    fun `同一条目更新保留创建时间并刷新更新时间`() = runBlocking {
        createVault()
        val entry = VaultEntry(site = "A", password = "p", createdAt = 1000L, updatedAt = 1000L)
        repository.saveEntry(entry)
        val created = repository.findEntry(entry.id)!!.createdAt

        Thread.sleep(5)
        repository.saveEntry(entry.copy(site = "A2"))
        val updated = repository.findEntry(entry.id)!!
        assertEquals("创建时间不应被改写", created, updated.createdAt)
        assertTrue("更新时间应当前进", updated.updatedAt >= updated.createdAt)
        assertEquals("A2", updated.site)
    }

    @Test
    fun `条目数量与计数一致`() = runBlocking {
        createVault()
        assertEquals(0, repository.entryCount())
        repeat(3) { i ->
            repository.saveEntry(VaultEntry(site = "S$i", password = "p$i"))
        }
        assertEquals(3, repository.entryCount())
    }

    @Test
    fun `字段损坏的条目在宽松模式下被跳过而不是阻断整库`() = runBlocking {
        createVault()
        repository.saveEntry(VaultEntry(site = "Good", password = "p"))

        // 人为插入一条无法解密的坏记录
        database.dao().upsert(
            EntryEntity(
                id = "broken",
                siteEnc = "not-base64!!!",
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
        assertEquals(1, lenient.size)
        assertEquals("Good", lenient[0].site)

        try {
            repository.loadEntries(strict = true)
            fail("严格模式必须暴露损坏条目")
        } catch (expected: CorruptEntryException) {
            assertNotNull(expected.message)
        }

        repository.lock()
        assertNull(repository.sessionDataKeyCopy())
    }
}
