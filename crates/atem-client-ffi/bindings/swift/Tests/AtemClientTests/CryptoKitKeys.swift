// An AppKeyProvider implemented in Swift with CryptoKit, the way Astation
// implements it (there with Secure Enclave keys and its owner-auth
// adapter): P-256 and Ed25519 signing, X25519, and HPKE open
// (.Curve25519_SHA256_ChachaPoly) for push hints. Keys here come from the
// r9 test vectors. Every signing request is recorded with its purpose.
#if canImport(CryptoKit)
import CryptoKit
import Foundation
@testable import AtemClient

final class CryptoKitKeys: AppKeyProvider, @unchecked Sendable {
    private enum Key {
        case p256(P256.Signing.PrivateKey)
        case ed25519(Curve25519.Signing.PrivateKey)
        case x25519(Curve25519.KeyAgreement.PrivateKey)
    }

    private var keys: [String: Key] = [:]
    private let lock = NSLock()
    private(set) var requests: [SignRequest] = []

    func addP256(_ id: String, secret: Data) throws { keys[id] = .p256(try P256.Signing.PrivateKey(rawRepresentation: secret)) }
    func addEd25519(_ id: String, seed: Data) throws { keys[id] = .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: seed)) }
    func addX25519(_ id: String, secret: Data) throws { keys[id] = .x25519(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret)) }

    private func key(_ id: String) throws -> Key {
        guard let k = keys[id] else { throw ProviderError.UnknownKey }
        return k
    }

    func publicKey(keyId: String) throws -> PublicKeyData {
        switch try key(keyId) {
        case .p256(let k): return PublicKeyData(alg: .p256, raw: k.publicKey.x963Representation)
        case .ed25519(let k): return PublicKeyData(alg: .ed25519, raw: k.publicKey.rawRepresentation)
        case .x25519(let k): return PublicKeyData(alg: .x25519, raw: k.publicKey.rawRepresentation)
        }
    }

    func sign(request: SignRequest) throws -> Data {
        lock.lock()
        requests.append(request)
        lock.unlock()
        switch try key(request.keyId) {
        case .p256(let k): return try k.signature(for: request.input).rawRepresentation
        case .ed25519(let k): return try k.signature(for: request.input)
        case .x25519: throw ProviderError.Failed(reason: "X25519 keys don't sign")
        }
    }

    func x25519(keyId: String, peer: Data) throws -> Data {
        guard case .x25519(let k) = try key(keyId) else { throw ProviderError.Failed(reason: "not X25519") }
        let shared = try k.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer))
        return shared.withUnsafeBytes { Data($0) }
    }

    func hpkeOpen(keyId: String, enc: Data, ct: Data, info: Data, aad: Data) throws -> Data {
        guard case .x25519(let k) = try key(keyId) else { throw ProviderError.Failed(reason: "not X25519") }
        guard #available(macOS 14.0, iOS 17.0, *) else { throw ProviderError.Failed(reason: "HPKE needs macOS 14 / iOS 17") }
        var recipient = try HPKE.Recipient(privateKey: k, ciphersuite: .Curve25519_SHA256_ChachaPoly, info: info, encapsulatedKey: enc)
        return try recipient.open(ct, authenticating: aad)
    }
}
#endif
