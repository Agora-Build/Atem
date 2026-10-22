// An AppKeyProvider implemented in Kotlin with the JDK's own crypto, the
// way an Android app implements it with the Keystore: P-256 and Ed25519
// signing, X25519, and RFC 9180 HPKE open (DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256, ChaCha20-Poly1305) for push hints. The keys here come from
// the r9 test vectors; a real app keeps them in the Keystore and never
// exports them. Every signing request is recorded with its purpose.
package atem.bindings.test

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import uniffi.atem_client_ffi.AppKeyProvider
import uniffi.atem_client_ffi.KeyAlg
import uniffi.atem_client_ffi.ProviderException
import uniffi.atem_client_ffi.PublicKeyData
import uniffi.atem_client_ffi.SignRequest

fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

fun unhex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

class JdkKeys : AppKeyProvider {
    private class Key(val alg: KeyAlg, val private: PrivateKey, val public: ByteArray)

    private val keys = HashMap<String, Key>()
    val requests = ArrayList<SignRequest>()

    fun addP256(id: String, secret: ByteArray, public: ByteArray) {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        val spec = ECPrivateKeySpec(BigInteger(1, secret), params.getParameterSpec(ECParameterSpec::class.java))
        keys[id] = Key(KeyAlg.P256, KeyFactory.getInstance("EC").generatePrivate(spec), public)
    }

    fun addEd25519(id: String, seed: ByteArray, public: ByteArray) {
        val spec = EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed)
        keys[id] = Key(KeyAlg.ED25519, KeyFactory.getInstance("Ed25519").generatePrivate(spec), public)
    }

    fun addX25519(id: String, secret: ByteArray, public: ByteArray) {
        val spec = XECPrivateKeySpec(NamedParameterSpec.X25519, secret)
        keys[id] = Key(KeyAlg.X25519, KeyFactory.getInstance("XDH").generatePrivate(spec), public)
    }

    private fun key(id: String) = keys[id] ?: throw ProviderException.UnknownKey()

    override fun publicKey(keyId: String): PublicKeyData {
        val k = key(keyId)
        return PublicKeyData(k.alg, k.public)
    }

    override fun sign(request: SignRequest): ByteArray {
        requests.add(request)
        val k = key(request.keyId)
        return when (k.alg) {
            KeyAlg.P256 -> {
                val s = Signature.getInstance("SHA256withECDSA")
                s.initSign(k.private)
                s.update(request.input)
                derToRaw(s.sign())
            }
            KeyAlg.ED25519 -> {
                val s = Signature.getInstance("Ed25519")
                s.initSign(k.private)
                s.update(request.input)
                s.sign()
            }
            KeyAlg.X25519 -> throw ProviderException.Failed("X25519 keys don't sign")
        }
    }

    override fun x25519(keyId: String, peer: ByteArray): ByteArray = dh(key(keyId), peer)

    override fun hpkeOpen(keyId: String, enc: ByteArray, ct: ByteArray, info: ByteArray, aad: ByteArray): ByteArray {
        val k = key(keyId)
        if (k.alg != KeyAlg.X25519) throw ProviderException.Failed("not an X25519 key")
        return Hpke.open(dh(k, enc), enc, k.public, ct, info, aad)
    }

    private fun dh(k: Key, peer: ByteArray): ByteArray {
        // RFC 7748 u-coordinate: little-endian, top bit masked.
        val u = peer.reversedArray()
        u[0] = (u[0].toInt() and 0x7f).toByte()
        val pub = KeyFactory.getInstance("XDH").generatePublic(XECPublicKeySpec(NamedParameterSpec.X25519, BigInteger(1, u)))
        val ka = KeyAgreement.getInstance("XDH")
        ka.init(k.private)
        ka.doPhase(pub, true)
        return ka.generateSecret()
    }

    companion object {
        /// DER ECDSA-Sig-Value → 64-byte r‖s.
        fun derToRaw(der: ByteArray): ByteArray {
            var i = 2
            if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7f
            fun int(): ByteArray {
                require(der[i].toInt() == 0x02)
                val len = der[i + 1].toInt()
                val v = der.copyOfRange(i + 2, i + 2 + len)
                i += 2 + len
                val trimmed = v.dropWhile { it.toInt() == 0 }.toByteArray()
                return ByteArray(32 - trimmed.size) + trimmed
            }
            return int() + int()
        }
    }
}

/// RFC 9180 base-mode open for the one suite of §R9.9.
object Hpke {
    private val suiteKem = "KEM".toByteArray() + byteArrayOf(0x00, 0x20)
    private val suite = "HPKE".toByteArray() + byteArrayOf(0x00, 0x20, 0x00, 0x01, 0x00, 0x03)
    private val v1 = "HPKE-v1".toByteArray()

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun extract(salt: ByteArray, suiteId: ByteArray, label: String, ikm: ByteArray) =
        hmac(salt, v1 + suiteId + label.toByteArray() + ikm)

    private fun expand(prk: ByteArray, suiteId: ByteArray, label: String, info: ByteArray, len: Int): ByteArray {
        val labeled = byteArrayOf((len shr 8).toByte(), len.toByte()) + v1 + suiteId + label.toByteArray() + info
        var t = ByteArray(0)
        var out = ByteArray(0)
        var n = 1
        while (out.size < len) {
            t = hmac(prk, t + labeled + byteArrayOf(n.toByte()))
            out += t
            n++
        }
        return out.copyOf(len)
    }

    fun open(dh: ByteArray, enc: ByteArray, pkR: ByteArray, ct: ByteArray, info: ByteArray, aad: ByteArray): ByteArray {
        val eaePrk = extract(ByteArray(0), suiteKem, "eae_prk", dh)
        val shared = expand(eaePrk, suiteKem, "shared_secret", enc + pkR, 32)
        val pskIdHash = extract(ByteArray(0), suite, "psk_id_hash", ByteArray(0))
        val infoHash = extract(ByteArray(0), suite, "info_hash", info)
        val context = byteArrayOf(0x00) + pskIdHash + infoHash
        val secret = extract(shared, suite, "secret", ByteArray(0))
        val key = expand(secret, suite, "key", context, 32)
        val nonce = expand(secret, suite, "base_nonce", context, 12)
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ct)
    }
}
