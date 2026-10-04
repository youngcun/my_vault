package com.myvault.password.data

import com.myvault.password.core.Base64Codec
import com.myvault.password.core.CryptoPrimitives
import com.myvault.password.core.EnvelopeCodec
import com.myvault.password.core.KeyEnvelope
import com.myvault.password.core.MasterKeyMaterial
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * 已解锁会话。
 *
 * 密钥材料只在这里保存，随 [VaultRepository.lock] 一起被清零。
 * 刻意不做任何「后台自动重新解锁」或密钥缓存到磁盘的行为。
 */
sealed interface VaultSession {
    data object NotInitialized : VaultSession
    data object Locked : VaultSession
    data class Unlocked(val keyId: String) : VaultSession
}

/** 完整性校验结果。 */
data class IntegrityReport(
    val totalEntries: Int,
    val badEntries: List<String>,
    val checksumMatches: Boolean,
    val expectedChecksum: String?,
    val actualChecksum: String,
) {
    val ok: Boolean get() = badEntries.isEmpty() && checksumMatches
}

/**
 * 一次解码的结果：成功的条目 + 解不开的条目 ID。
 *
 * 把「解不开」单独列出来，是为了让界面能明确告诉用户
 * 「有 N 条记录无法解密」，而不是让它们悄悄消失。
 */
data class DecodeResult(
    val entries: List<com.myvault.password.domain.VaultEntry>,
    val brokenEntryIds: List<String>,
)

/**
 * 密码库仓储：应用内唯一持有解密能力的地方。
 *
 * 职责边界
 * -------
 *  - 持有 [MasterKeyMaterial]（唯一的内存明文密钥），并负责其生命周期；
 *  - 负责「解密后再交给 UI」这一唯一路径，UI 层拿不到密文也拿不到子密钥；
 *  - 维护库级 HMAC 校验和，提供可主动重跑的完整性证明。
 *
 * 线程模型：所有数据库与 KDF 操作都切到 [Dispatchers.IO]。Argon2id 在
 * 主线程执行会因为数百毫秒的 CPU 占用触发 ANR，这是安全应用最常见
 * 的可用性事故之一。
 */
class VaultRepository(
    private val dao: VaultDao,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    @Volatile
    private var material: MasterKeyMaterial? = null

    private val _session = MutableStateFlow<VaultSession>(VaultSession.NotInitialized)
    val session: StateFlow<VaultSession> = _session.asStateFlow()

    /** 最近一次成功解锁的密钥标识，便于设置页展示。 */
    val currentEnvelope: KeyEnvelope?
        get() = material?.envelope

    val isUnlocked: Boolean get() = material != null

    // ------------------------------------------------------------ 初始化

    /** 是否存在已创建的密码库。 */
    suspend fun isInitialized(): Boolean = withContext(Dispatchers.IO) {
        val initialized = dao.loadEnvelope() != null
        if (!initialized && _session.value == VaultSession.NotInitialized) {
            _session.value = VaultSession.NotInitialized
        }
        initialized
    }

    /** 重新读取会话状态（进程重启后调用）。 */
    suspend fun refreshSessionState() {
        val initialized = withContext(Dispatchers.IO) { dao.loadEnvelope() != null }
        if (!initialized) {
            _session.value = VaultSession.NotInitialized
        } else if (material == null) {
            _session.value = VaultSession.Locked
        }
    }

    /** 初始创建：生成全新信封与数据密钥。 */
    suspend fun createVault(password: CharArray): Unit = withContext(Dispatchers.IO) {
        require(dao.loadEnvelope() == null) { "密码库已存在，不能重复创建" }
        val (env, mat) = EnvelopeCodec.createEnvelope(password)
        try {
            dao.saveEnvelope(EnvelopeEntity(json = EnvelopeCodec.toJson(env), updatedAt = clock()))
            dao.saveMeta(VaultMetaEntity(checksum = null, lastVerifiedAt = null))
            material = mat
            _session.value = VaultSession.Unlocked(env.keyId)
            // 新库还没有任何条目，但「已解锁」必须立刻成立
            com.myvault.password.autofill.UnlockedEntryCache.markUnlocked()
            recomputeChecksumInternal()
        } catch (e: Exception) {
            mat.destroy()
            throw e
        }
    }

    // ------------------------------------------------------------ 解锁 / 锁定

    /** 主密码解锁。口令错误时抛 [com.myvault.password.core.WrongSecretException]。 */
    suspend fun unlockWithPassword(password: CharArray) = withContext(Dispatchers.IO) {
        val entity = dao.loadEnvelope() ?: error("密码库尚未创建")
        val env = EnvelopeCodec.fromJson(entity.json)
        // Argon2id 在这里执行；失败（密码错误）时不会留下任何密钥材料
        val mat = EnvelopeCodec.unwrap(env, password)
        installSession(mat)
    }

    /**
     * 指纹解锁：调用方必须先用 [KeystoreManager] 完成生物识别并解出数据密钥。
     *
     * 本方法会校验解出的密钥长度，并把它与当前信封绑定成会话。
     * 注意：此处不重新校验信封 MAC —— 因为算 MAC 需要 KEK（来自主密码），
     * 而指纹路径本来就没有主密码。这不是弱点：指纹包裹层由 TEE 保护的
     * 硬件密钥加密，能解开它本身就证明了访问权的合法性。
     */
    suspend fun unlockWithBiometricKey(dataKey: ByteArray) = withContext(Dispatchers.IO) {
        val entity = dao.loadEnvelope() ?: error("密码库尚未创建")
        val env = EnvelopeCodec.fromJson(entity.json)
        EnvelopeCodec.assertBiometricUsable(env)
        require(dataKey.size == CryptoPrimitives.AES_KEY_BYTES) {
            "指纹返回的密钥长度非法：${dataKey.size}"
        }
        installSession(MasterKeyMaterial(dataKey.copyOf(), env.keyId, env))
    }

    private fun installSession(mat: MasterKeyMaterial) {
        val previous = material
        material = mat
        _session.value = VaultSession.Unlocked(mat.keyId)
        // 解锁完成即视为「填充服务可用」：条目那条 Flow 可能还没发射第一次，
        // 那个间隙里自动填充会误报「库已锁定」
        com.myvault.password.autofill.UnlockedEntryCache.markUnlocked()
        // 旧会话（例如「修改主密码」后重建）必须清零，避免内存里同时存在两份密钥
        if (previous !== mat) previous?.destroy()
    }

    /**
     * 锁定：清零内存中的密钥材料。
     *
     * 同时清空自动填充用的明文快照 —— 这两件事必须成对发生，
     * 否则会出现「库已锁定但自动填充仍能取到明文」的严重缺口。
     */
    suspend fun lock() {
        material?.destroy()
        material = null
        // KEK 缓存也必须清零：它虽然不能单独解出数据（还需要 Keystore 的 DEK），
        // 但锁定的语义是「内存里不再留有可用于解密的东西」。
        com.myvault.password.core.EnvelopeCodec.clearKeyCache()
        com.myvault.password.autofill.UnlockedEntryCache.clear()
        _session.value = VaultSession.Locked
    }

    private fun requireMaterial(): MasterKeyMaterial =
        material ?: error("密码库已锁定")

    // ------------------------------------------------------------ 读取

    /**
     * 监听全部条目（解密后的明文）。数据库变化会自动推送新值。
     *
     * 每次发射都会同步刷新进程内的自动填充快照 —— 这是**唯一**填充服务
     * 能看到明文的渠道，因此必须与库状态严格一致。
     *
     * 解不开的条目**不会被静默丢弃**：它的 id 会通过
     * [observeDecodeResults] 暴露给界面，让用户知道「有一条记录读不出来」。
     * 静默丢弃曾经掩盖了一个真实缺陷（保存成功但读回失败）。
     */
    fun observeEntries(): Flow<List<com.myvault.password.domain.VaultEntry>> =
        observeDecodeResults().map { it.entries }

    /**
     * 同时给出「成功解密的条目」与「无法解密的条目 ID」。
     *
     * 之所以把损坏条目单独暴露：容错跳过是必要的（一条坏数据不该让整库打不开），
     * 但**必须让用户看得见**，否则保存失败会表现得像「什么都没发生」。
     */
    fun observeDecodeResults(): Flow<DecodeResult> =
        dao.observeAll().map { list ->
            val decoded = ArrayList<com.myvault.password.domain.VaultEntry>(list.size)
            val broken = ArrayList<String>()
            for (row in list) {
                val entry = safeDecode(row)
                if (entry != null) decoded.add(entry) else broken.add(row.id)
            }
            com.myvault.password.autofill.UnlockedEntryCache.update(decoded)
            DecodeResult(decoded, broken)
        }

    /**
     * 一次性读取全部条目。
     *
     * @param strict 为 true 时任何一条解密失败都会抛出异常（用于完整性校验）；
     *               为 false 时跳过损坏条目并继续（用于列表展示，避免一条坏数据
     *               导致整个密码库无法打开）。
     */
    suspend fun loadEntries(strict: Boolean = false): List<com.myvault.password.domain.VaultEntry> =
        withContext(Dispatchers.IO) {
            val cipher = FieldCipher(requireMaterial())
            val rows = dao.loadAll()
            if (strict) {
                rows.map { cipher.fromEntity(it) }
            } else {
                rows.mapNotNull { safeDecode(it) }
            }
        }

    private fun safeDecode(entity: EntryEntity): com.myvault.password.domain.VaultEntry? = try {
        val m = material ?: return null
        FieldCipher(m).fromEntity(entity)
    } catch (e: CorruptEntryException) {
        // 单条损坏不应让整个库打不开；安全自证页面会把它报出来
        null
    }

    suspend fun findEntry(id: String): com.myvault.password.domain.VaultEntry? = withContext(Dispatchers.IO) {
        val row = dao.loadById(id) ?: return@withContext null
        safeDecode(row)
    }

    /**
     * 为自动填充查找候选条目，按匹配度排序。
     * 只在内存中对已解密条目做匹配，不额外持久化任何索引。
     */
    suspend fun findCandidates(host: String?, packageName: String?): List<com.myvault.password.domain.VaultEntry> {
        val all = loadEntries()
        return all.map { it to it.matchScore(host, packageName) }
            .filter { it.second > 0 }
            .sortedByDescending { it.second }
            .map { it.first }
    }

    // ------------------------------------------------------------ 写入

    /**
     * 新增或更新条目，并同步刷新库级校验和。
     *
     * 返回真正写入数据库的那条记录，让调用方可以立即做一次回读验证 ——
     * 「写入成功但读不回来」曾经是一个真实缺陷，回读是发现它的最快方式。
     */
    suspend fun saveEntry(
        entry: com.myvault.password.domain.VaultEntry,
    ): com.myvault.password.domain.VaultEntry = withContext(Dispatchers.IO) {
        val m = requireMaterial()
        val now = clock()
        val existing = dao.loadById(entry.id)
        val toSave = entry.copy(
            createdAt = existing?.createdAt ?: entry.createdAt,
            updatedAt = now,
        )
        dao.upsert(FieldCipher(m).toEntity(toSave))
        recomputeChecksumInternal()
        toSave
    }

    suspend fun deleteEntry(id: String) = withContext(Dispatchers.IO) {
        dao.deleteById(id)
        recomputeChecksumInternal()
    }

    suspend fun setFavorite(id: String, favorite: Boolean) = withContext(Dispatchers.IO) {
        dao.setFavorite(id, favorite, clock())
    }

    // ------------------------------------------------------------ 主密码 / 指纹

    /** 修改主密码：只重写信封，条目不重新加密。 */
    suspend fun changeMasterPassword(current: CharArray, newPassword: CharArray) =
        withContext(Dispatchers.IO) {
            val m = requireMaterial()
            val env = EnvelopeCodec.fromJson(
                dao.loadEnvelope()?.json ?: error("密码库尚未创建"),
            )
            // 先验证当前口令，避免「已解锁会话」被用来绕过口令确认
            val verified = EnvelopeCodec.unwrap(env, current)
            verified.destroy()

            val (newEnv, newMaterial) = EnvelopeCodec.rewrapWithPassword(env, m, newPassword)
            try {
                dao.saveEnvelope(EnvelopeEntity(json = EnvelopeCodec.toJson(newEnv), updatedAt = clock()))
                // 主密码已更换：旧 KEK 对应的 salt 也已改变，缓存必须作废
                com.myvault.password.core.EnvelopeCodec.clearKeyCache()
                installSession(newMaterial)
            } catch (e: Exception) {
                newMaterial.destroy()
                throw e
            }
        }

    /**
     * 启用指纹解锁。
     *
     * @param keystoreWrapped 已由 Keystore 生物识别密钥加密的数据密钥（`IV||密文||Tag`）
     */
    suspend fun enableBiometric(
        password: CharArray,
        keystoreWrapped: ByteArray,
        aliasSuffix: String,
    ) = withContext(Dispatchers.IO) {
        val env = EnvelopeCodec.fromJson(dao.loadEnvelope()?.json ?: error("密码库尚未创建"))
        val (newEnv, newMaterial) = EnvelopeCodec.attachBiometricWithPassword(
            env, password, keystoreWrapped, aliasSuffix,
        )
        try {
            dao.saveEnvelope(EnvelopeEntity(json = EnvelopeCodec.toJson(newEnv), updatedAt = clock()))
            installSession(newMaterial)
        } catch (e: Exception) {
            newMaterial.destroy()
            throw e
        }
    }

    /** 关闭指纹解锁（需要主密码确认）。 */
    suspend fun disableBiometric(password: CharArray) = withContext(Dispatchers.IO) {
        val env = EnvelopeCodec.fromJson(dao.loadEnvelope()?.json ?: error("密码库尚未创建"))
        val (newEnv, newMaterial) = EnvelopeCodec.detachBiometric(env, password)
        try {
            dao.saveEnvelope(EnvelopeEntity(json = EnvelopeCodec.toJson(newEnv), updatedAt = clock()))
            installSession(newMaterial)
        } catch (e: Exception) {
            newMaterial.destroy()
            throw e
        }
    }

    /** 当前信封中记录的指纹别名后缀。 */
    suspend fun biometricAliasSuffix(): String? = withContext(Dispatchers.IO) {
        val env = EnvelopeCodec.fromJson(dao.loadEnvelope()?.json ?: return@withContext null)
        env.biometricAlias
    }

    fun isBiometricEnabled(): Boolean = material?.envelope?.biometricWrap != null

    /**
     * 取当前会话数据密钥的一份副本。
     *
     * 仅供「把 DEK 交给 Android Keystore 加密以启用指纹」这一条路径使用。
     * 调用方**必须**在用完后清零返回的数组。之所以返回副本而不是暴露
     * 内部的 [MasterKeyMaterial]，是为了让「谁可能泄露密钥」这件事在
     * 代码里保持显式、可审计。
     */
    fun sessionDataKeyCopy(): ByteArray? = material?.dataKey?.copyOf()

    // ------------------------------------------------------------ 完整性

    /**
     * 全库完整性校验。
     *
     * 逐条尝试解密（GCM 认证），再重算库级 HMAC 与存储值比对。
     * 这是本应用「可自证」承诺的具体兑现方式：用户点一下就能知道
     * 数据库文件有没有被本应用之外的东西改动过。
     */
    suspend fun verifyIntegrity(): IntegrityReport = withContext(Dispatchers.IO) {
        val m = requireMaterial()
        val cipher = FieldCipher(m)
        val rows = dao.loadAllForIntegrity()
        val bad = ArrayList<String>()
        for (row in rows) {
            try {
                // 解密全部字段即可验证每条密文的 GCM 认证标签
                cipher.fromEntity(row)
            } catch (e: CorruptEntryException) {
                bad.add(row.id)
            }
        }
        val actual = computeChecksum(cipher, rows)
        val stored = dao.loadMeta()?.checksum
        val report = IntegrityReport(
            totalEntries = rows.size,
            badEntries = bad,
            checksumMatches = stored != null && stored == actual,
            expectedChecksum = stored,
            actualChecksum = actual,
        )
        dao.saveMeta(
            (dao.loadMeta() ?: VaultMetaEntity()).copy(
                checksum = if (report.checksumMatches) stored else actual,
                lastVerifiedAt = clock(),
                lastBadCount = bad.size,
            ),
        )
        report
    }

    /** 写入任何变更后刷新校验和。 */
    private suspend fun recomputeChecksumInternal() {
        val m = material ?: return
        val rows = dao.loadAllForIntegrity()
        val checksum = computeChecksum(FieldCipher(m), rows)
        val meta = dao.loadMeta() ?: VaultMetaEntity()
        dao.saveMeta(meta.copy(checksum = checksum))
    }

    /**
     * 计算覆盖全库的 HMAC-SHA256。
     *
     * 输入是「规范化后的密文本身」而不是明文：
     *  - 密文已经由 GCM 认证，篡改密文会在解密阶段暴露；
     *  - 用密文算校验和不需要把全部明文读进内存，降低暴露面；
     *  - 同时把 [EntryEntity.fav] 等明文元数据纳入，覆盖「偷偷取消收藏」这类改动。
     */
    private fun computeChecksum(cipher: FieldCipher, rows: List<EntryEntity>): String {
        val m = requireMaterial()
        val digest = MessageDigest.getInstance("SHA-256")
        // 排序保证顺序无关，避免 SQLite 返回顺序变化导致误报
        for (row in rows.sortedBy { it.id }) {
            digest.update(row.id.toByteArray(Charsets.UTF_8))
            for (ct in row.ciphertexts()) {
                digest.update(ct.toByteArray(Charsets.UTF_8))
                digest.update(0)
            }
            digest.update((if (row.fav) 1 else 0).toByte())
            digest.update((if (row.generated) 1 else 0).toByte())
            digest.update(row.createdAt.toString().toByteArray(Charsets.UTF_8))
            digest.update(row.updatedAt.toString().toByteArray(Charsets.UTF_8))
        }
        val canonical = digest.digest()
        val mac = CryptoPrimitives.hmacSha256(m.macKey, canonical)
        return Base64Codec.encode(mac)
    }

    // ------------------------------------------------------------ 备份导入导出

    /** 供备份模块读取全部明文条目。 */
    suspend fun snapshotForBackup(): List<com.myvault.password.domain.VaultEntry> = loadEntries(strict = true)

    /**
     * 校验主密码是否正确。
     *
     * 用途：导出备份时若用户选择「使用主密码作为备份口令」，
     * **必须**先确认他输入的主密码是对的 —— 否则备份会被一个错误口令加密，
     * 等到真正需要恢复时才发现打不开，那时已经太晚了。
     *
     * 实现复用唯一的真值来源（尝试解开当前密钥信封），
     * 不为备份流程单独维护一份口令哈希。
     *
     * @return true 表示口令正确
     */
    suspend fun verifyMasterPassword(password: CharArray): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val env = EnvelopeCodec.fromJson(
                dao.loadEnvelope()?.json ?: return@runCatching false,
            )
            // 解出的密钥材料仅用于验证，立即销毁
            EnvelopeCodec.unwrap(env, password).destroy()
            true
        }.getOrDefault(false)
    }

    /**
     * 备份恢复：批量写入条目。
     *
     * 除了「导入了几条 / 按 ID 跳过几条」，还额外报出**名称重名**：
     * 同一个站点 / 应用名称在恢复后出现多条记录时，程序无法判断这是
     * 「同一账号的第二个密码」还是「不小心导入了两遍」——这只有用户能判断。
     * 因此绝不静默：名字会被带回去，由调用方写进操作日志并提示用户。
     *
     * 重名有两种来源，都会被检出：
     *  1. 与库内**其他**条目同名（ID 不同，导入后两条会并存）；
     *  2. 备份文件**内部**彼此同名（一份整理得不好的备份里很常见）。
     *
     * 刻意**不**把「覆盖同一个 ID」算作重名：那条旧记录随后会被替换掉，
     * 若它在库内没有别的同名记录，就不存在并存问题。否则每次覆盖恢复
     * 都会刷出一堆假重名，真重名反而被淹没。
     *
     * @param overwriteExisting 为 true 时同 ID 条目会被覆盖写入，否则跳过
     */
    suspend fun restoreEntries(
        entries: List<com.myvault.password.domain.VaultEntry>,
        overwriteExisting: Boolean,
    ): com.myvault.password.operationlog.RestoreReport = withContext(Dispatchers.IO) {
        val m = requireMaterial()
        val cipher = FieldCipher(m)
        val existing = dao.loadAll()

        // 库内已有的名称 → 拥有该名称的条目 ID。
        // 站点名是加密字段，必须逐条解密才能比较 —— 这是必要的代价：
        // 只有比对明文名称才能发现「导进来两条一模一样的支付宝」。
        // 这里刻意先建好映射（而不是在循环里反复解密）：
        // 恢复几百条备份时，重复解密会让导入慢到肉眼可见。
        val namesById = existing.associate { it.id to safeDecode(it)?.site?.trim().orEmpty() }
        val idsByName = HashMap<String, MutableList<String>>()
        for (row in existing) {
            val name = namesById[row.id].orEmpty()
            if (name.isNotEmpty()) idsByName.getOrPut(name) { ArrayList() }.add(row.id)
        }

        var imported = 0
        var skipped = 0
        val duplicates = LinkedHashSet<String>()
        val seenIncoming = HashSet<String>()
        val toWrite = ArrayList<EntryEntity>(entries.size)

        for (e in entries) {
            if (namesById.containsKey(e.id) && !overwriteExisting) {
                skipped++
                continue
            }
            val name = e.site.trim()
            if (name.isNotEmpty()) {
                // 重名判定：库内已有别的条目同名，或本次备份里前面已出现过同名。
                // 注意「同一个 ID 被覆盖」的情形：旧记录随后会被替换掉，
                // 若它在库内没有别的同名记录，就不该算作重名 ——
                // 否则每次覆盖恢复都会刷出一堆假重名，真重名反而被淹没。
                val existingIdsWithName = idsByName[name].orEmpty()
                val conflictsWithExisting = existingIdsWithName.any { id -> id != e.id }
                if (conflictsWithExisting || !seenIncoming.add(name)) {
                    duplicates += name
                }
            }
            toWrite.add(cipher.toEntity(e))
            imported++
        }
        if (toWrite.isNotEmpty()) {
            dao.upsertAll(toWrite)
            recomputeChecksumInternal()
        }
        com.myvault.password.operationlog.RestoreReport(
            imported = imported,
            skipped = skipped,
            duplicateSiteNames = duplicates.toList(),
        )
    }

    /** 清空全部数据（用于「从备份完整覆盖」之外的危险操作，界面上需二次确认）。 */
    suspend fun wipeAll() = withContext(Dispatchers.IO) {
        dao.deleteAll()
        dao.clearMeta()
    }

    /** 已解锁时返回库内条目数，用于设置页摘要。 */
    suspend fun entryCount(): Int = withContext(Dispatchers.IO) { dao.count() }

    /** 调试/测试辅助：等待第一条数据库发射。 */
    internal suspend fun firstSnapshot(): List<EntryEntity> = dao.observeAll().first()
}

/** Room 数据库 → 仓储的构建入口。 */
object VaultRepositoryFactory {
    fun create(dao: VaultDao): VaultRepository = VaultRepository(dao)
}
