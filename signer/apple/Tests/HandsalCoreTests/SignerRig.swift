import CryptoKit
import Foundation
import HandsalCore
import Testing

/// What every signer test needs: a software backend, a recording display, a fixed clock and nonce,
/// and a prompt guard on a private lock file. One owner, so no test builds its own environment.
struct Rig {
    let backend: SoftwareBackend
    let display: RecordingDisplay?
    let env: Environment
    let lockPath: String

    static let ts = "2026-11-08T11:59:00Z"
    static let nonce = Encoding.hashstr(Array("nonce".utf8))

    init(person: String? = "alice", keyClass: String = "test-sw-p256", display: RecordingDisplay? = RecordingDisplay(),
         maxPrompts: Int = 1_000, label: String = "laptop", scalar: [UInt8]? = nil) {
        let backend = SoftwareBackend(keyClass: keyClass, scalar: scalar)
        if let person { _ = try? backend.create(label: label, person: person) { _ in } }
        let path = NSTemporaryDirectory() + "handsal-test-\(UUID().uuidString).lock"
        let shown = display
        self.backend = backend
        self.display = display
        self.lockPath = path
        self.env = Environment(
            backend: backend,
            display: { if let shown { return shown }; throw Refusal("no_display") },
            now: { Forms.epochSeconds(Rig.ts)! },
            nonce: { Rig.nonce },
            prompts: PromptGuard(lockPath: path, maxPrompts: maxPrompts, perSeconds: 60, clock: { Forms.epochSeconds(Rig.ts)! }))
    }

    func run(_ args: [String], _ stdin: [UInt8] = []) -> Outcome {
        CLI.run(arguments: args, readStdin: { stdin }, environment: env)
    }

    func run(_ args: [String], _ input: JValue) -> Outcome {
        run(args, (try? Emit.subset(input)) ?? [])
    }

    var material: KeyMaterial? { try? backend.bound() }
}

func hsh(_ seed: String) -> String { Encoding.hashstr(Array(seed.utf8)) }
func jstr(_ s: String) -> JValue { .string(s) }
func lineText(_ outcome: Outcome) -> String { String(decoding: outcome.line, as: UTF8.self) }

/// The JSON object an outcome's line holds, read by the test-only reader.
func resultObject(_ outcome: Outcome) -> [String: JValue] {
    guard case .object(let o)? = try? TestJSON.parse(outcome.line) else { return [:] }
    return o
}

func errorLine(_ code: String) -> String { #"{"error":"\#(code)"}"# }

/// A verdict draft for `person`, the default recipient of the rig.
func verdictDraft(recipient: String = "alice", request: String = "req-00000001") -> JValue {
    .object(["body": .object([:]), "expires_in_s": jstr("3600"), "head": .object(["id": jstr(hsh("h")), "kind": jstr("chain")]),
             "method": jstr(Methods.approve), "org": jstr(hsh("org")), "recipient": jstr(recipient), "relay": jstr("r.example"),
             "request_id": jstr(request)])
}

let requestB64 = "ZGVwbG95IHYy"  // "deploy v2"

func chainDraft(parent: String = hsh("p")) -> JValue {
    .object(["body": .object(["kid": jstr("NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY"), "person": jstr("carol")]),
             "method": jstr(Methods.deviceRemove), "org": jstr(hsh("org")), "parent": .object(["id": jstr(parent), "performer": jstr("bob")])])
}

func signInput(_ draft: JValue, _ attachments: JValue = .object([:])) -> JValue {
    .object(["attachments": attachments, "draft": draft])
}

/// The ES256 public key of a rig's material.
func publicKey(_ material: KeyMaterial) throws -> P256.Signing.PublicKey {
    let x = try #require(Encoding.base64urlDecode(material.sign.x))
    let y = try #require(Encoding.base64urlDecode(material.sign.y))
    return try P256.Signing.PublicKey(x963Representation: Data([0x04] + x + y))
}

struct SplitJWS {
    let header: [UInt8], payload: [UInt8], signature: [UInt8], signingInput: [UInt8]
    init?(_ jws: String) {
        let parts = jws.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, let h = Encoding.base64urlDecode(parts[0]), let p = Encoding.base64urlDecode(parts[1]),
              let s = Encoding.base64urlDecode(parts[2]) else { return nil }
        header = h; payload = p; signature = s
        signingInput = Array((parts[0] + "." + parts[1]).utf8)
    }
}

/// The three parts of the JWS a `sign` outcome holds.
func jwsParts(of outcome: Outcome) throws -> SplitJWS {
    let jws = try #require(resultObject(outcome)["jws"]?.str)
    return try #require(SplitJWS(jws))
}
