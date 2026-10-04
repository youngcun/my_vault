package com.myvault.password.core

/**
 * 易记口令词表。
 *
 * 为什么自己带词表而不是下载 Diceware 表
 * ------------------------------------
 * 1. **离线优先**：词表编译进 APK，运行期零文件、零网络访问，符合「零网络权限」承诺；
 * 2. **可审计**：词表内容是纯文本资源，用户可以自己打开数一数、检查有没有奇怪的词；
 * 3. 简洁起见只收录 3~8 个字母、全部小写 ASCII 的常见英文词 —— 这类词打字快、
 *    在不同输入法/键盘上都不易出错，且长度相近让口令长度可预测。
 *
 * 熵的计算
 * -------
 * 每个词贡献 log2(词表大小) 比特：
 *   - CORE     2048 词 → 11 bit/词，5 词 = 55 bit，6 词 = 66 bit
 *   - EXTENDED 4096 词 → 12 bit/词，5 词 = 60 bit，6 词 = 72 bit
 * 作为对比，一个 8 位「大小写+数字+符号」的随机口令约 52 bit。
 *
 * 词表加载是惰性的：只有用户真的选择「易记模式」时才会读取资源，
 * 常规随机口令路径不会产生任何 IO。
 */
object WordList {

    const val CORE_SIZE = 2048
    const val EXTENDED_SIZE = 4096

    private const val RESOURCE_PATH = "/wordlist/myvault_words.txt"

    @Volatile
    private var cache: List<String>? = null

    /**
     * 返回按 [size] 档位截取后的词表。
     *
     * 档位规则（必须与 [PasswordEntropy.bitsOf] 的假设严格一致，
     * 否则界面会显示错误的熵值）：
     *  - `size >= EXTENDED_SIZE` → 返回前 [EXTENDED_SIZE] 个词；
     *  - 其余情况               → 返回前 [CORE_SIZE] 个词。
     *
     * 注意不能写成「不够就返回全部」—— 那会让熵公式高估实际词表规模。
     * 词表按长度从短到长排列，因此 CORE 档位自动取到更短、更易记的词。
     */
    fun words(size: Int): List<String> {
        val all = allWords()
        val capped = if (size >= EXTENDED_SIZE) EXTENDED_SIZE else CORE_SIZE
        return if (all.size >= capped) all.subList(0, capped) else all
    }

    /** 全部词（去重、已校验）。首次调用时从 APK 资源加载。 */
    fun allWords(): List<String> {
        cache?.let { return it }
        synchronized(this) {
            cache?.let { return it }
            val loaded = load()
            cache = loaded
            return loaded
        }
    }

    /** 词表实际条数（供安全审计界面展示）。 */
    fun actualSize(): Int = allWords().size

    private fun load(): List<String> {
        val stream = WordList::class.java.getResourceAsStream(RESOURCE_PATH)
            ?: return emptyList()
        val out = ArrayList<String>(EXTENDED_SIZE)
        val seen = HashSet<String>(EXTENDED_SIZE * 2)
        stream.bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (raw in lines) {
                val w = raw.trim().lowercase()
                if (w.isEmpty() || w.startsWith("#")) continue
                // 只接受 3~8 个纯小写字母的词，杜绝资源文件被污染导致口令异常
                if (w.length !in 3..8) continue
                if (!w.all { it in 'a'..'z' }) continue
                if (seen.add(w)) out.add(w)
            }
        }
        return out
    }
}
