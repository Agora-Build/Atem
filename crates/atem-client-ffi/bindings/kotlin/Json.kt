// A small JSON reader/writer for the conformance and end-to-end tests (the
// JDK has none). Objects keep their key order; integers are Long.
package atem.bindings.test

object Json {
    fun parse(text: String): Any? {
        val p = Parser(text)
        val v = p.value()
        p.ws()
        require(p.i == text.length) { "trailing data at ${p.i}" }
        return v
    }

    fun write(v: Any?): String = StringBuilder().also { write(v, it) }.toString()

    private fun write(v: Any?, out: StringBuilder) {
        when (v) {
            null -> out.append("null")
            is String -> {
                out.append('"')
                for (c in v) {
                    when {
                        c == '"' -> out.append("\\\"")
                        c == '\\' -> out.append("\\\\")
                        c < ' ' -> out.append(String.format("\\u%04x", c.code))
                        else -> out.append(c)
                    }
                }
                out.append('"')
            }
            is Boolean, is Long, is Int -> out.append(v.toString())
            is Map<*, *> -> {
                out.append('{')
                var first = true
                for ((k, value) in v) {
                    if (!first) out.append(',')
                    first = false
                    write(k as String, out)
                    out.append(':')
                    write(value, out)
                }
                out.append('}')
            }
            is List<*> -> {
                out.append('[')
                v.forEachIndexed { i, value ->
                    if (i > 0) out.append(',')
                    write(value, out)
                }
                out.append(']')
            }
            else -> error("can't write ${v::class}")
        }
    }

    private class Parser(val s: String) {
        var i = 0

        fun ws() {
            while (i < s.length && s[i] in " \t\r\n") i++
        }

        fun value(): Any? {
            ws()
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> { expect("true"); true }
                'f' -> { expect("false"); false }
                'n' -> { expect("null"); null }
                else -> num()
            }
        }

        fun expect(word: String) {
            require(s.startsWith(word, i)) { "bad literal at $i" }
            i += word.length
        }

        fun obj(): Map<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            i++
            ws()
            if (s[i] == '}') { i++; return out }
            while (true) {
                ws()
                val k = str()
                ws()
                require(s[i] == ':') { "expected : at $i" }
                i++
                out[k] = value()
                ws()
                if (s[i] == ',') { i++; continue }
                require(s[i] == '}') { "expected } at $i" }
                i++
                return out
            }
        }

        fun arr(): List<Any?> {
            val out = ArrayList<Any?>()
            i++
            ws()
            if (s[i] == ']') { i++; return out }
            while (true) {
                out.add(value())
                ws()
                if (s[i] == ',') { i++; continue }
                require(s[i] == ']') { "expected ] at $i" }
                i++
                return out
            }
        }

        fun str(): String {
            require(s[i] == '"') { "expected string at $i" }
            i++
            val out = StringBuilder()
            while (true) {
                val c = s[i++]
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> {
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> out.append(e)
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000c')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> { out.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                            else -> error("bad escape at $i")
                        }
                    }
                    else -> out.append(c)
                }
            }
        }

        fun num(): Any {
            val start = i
            while (i < s.length && (s[i].isDigit() || s[i] in "-+.eE")) i++
            val t = s.substring(start, i)
            return t.toLongOrNull() ?: t.toDouble()
        }
    }
}

@Suppress("UNCHECKED_CAST")
fun Any?.obj(): Map<String, Any?> = this as Map<String, Any?>

@Suppress("UNCHECKED_CAST")
fun Any?.arr(): List<Any?> = this as List<Any?>

fun Any?.s(): String = this as String

fun Any?.l(): Long = this as Long

@Suppress("UNCHECKED_CAST")
operator fun Any?.get(key: String): Any? = (this as Map<String, Any?>).get(key)

@Suppress("UNCHECKED_CAST")
operator fun Any?.get(index: Int): Any? = (this as List<Any?>).get(index)
