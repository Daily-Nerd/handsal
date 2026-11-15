import CryptoKit
import Foundation
import HandsalCore
import HandsalSecureEnclave
import LocalAuthentication
import Testing

/// T5.13: everything about the Secure Enclave backend that does not need a finger. What does
/// (Touch ID prompts, a changed fingerprint set, the real key) is the manual list in the report.
@Suite("Secure Enclave backend: the parts that need no hardware (T5.13)")
struct SecureEnclaveTests {
    private func tempDirectory() -> String { NSTemporaryDirectory() + "handsal-se-\(UUID().uuidString)" }

    private func stored(person: String = "alice", label: String = "laptop") -> StoredKey {
        StoredKey(label: label, person: person, keyClass: "apple-se-bio",
                  sign: Point(x: Encoding.base64url([UInt8](repeating: 1, count: 32)), y: Encoding.base64url([UInt8](repeating: 2, count: 32))),
                  agree: Point(x: Encoding.base64url([UInt8](repeating: 3, count: 32)), y: Encoding.base64url([UInt8](repeating: 4, count: 32))),
                  signBlob: [UInt8](repeating: 0xAA, count: 300), agreeBlob: [UInt8](repeating: 0xBB, count: 300))
    }

    @Test func theBackendProducesTheAppleBiometricClass() {
        #expect(SecureEnclaveBackend(directory: tempDirectory()).keyClass == "apple-se-bio")
        #expect((try? SecureEnclaveBackend.defaultDirectory())?.hasSuffix("/Library/Application Support/handsal-sign") == true)
    }

    /// SH12: a uid the directory service has no home for is the signer faulty (`internal`, exit 5), loudly. It is not a
    /// substitute folder, and not `key_unavailable`, which would name a missing key that was never looked for.
    @Test func aUidWithoutAHomeIsInternalNotAMadeUpFolderAndNotAMissingKey() {
        #expect(throws: Refusal.self) { try SecureEnclaveBackend.directory(home: { nil }) }
        do { _ = try SecureEnclaveBackend.directory(home: { nil }) } catch let refusal as Refusal {
            #expect(refusal.code == "internal")
            #expect(ExitCodes.outcome(for: refusal).exit == 5)
        } catch { Issue.record("not a refusal: \(error)") }
        #expect((try? SecureEnclaveBackend.directory(home: { "/Users/acme" })) == "/Users/acme/Library/Application Support/handsal-sign")
    }

    private func realHome() -> String {
        var record = passwd(), found: UnsafeMutablePointer<passwd>? = nil
        var buffer = [CChar](repeating: 0, count: 16384)
        #expect(getpwuid_r(getuid(), &record, &buffer, buffer.count, &found) == 0 && found != nil)
        return String(cString: record.pw_dir)
    }

    /// SH12, SG-14: the built signer looks for its key under the home the directory service gives for the real uid.
    /// `HOME` and `CFFIXED_USER_HOME` belong to whoever started the process, so a program that sets them must not move
    /// the key folder. A key with known public points is planted under a folder those variables name, and the signer
    /// runs `render` (it reads the key for the performer and kid, and needs no display) as a child with them set: this
    /// process's environment is never touched. If the signer looked in the planted folder, the text it prints would
    /// carry the planted performer and kid. That holds whatever key the real user has.
    @Test func theSignerKeyFolderIsUnderTheHomeOfTheRealUserWhateverTheEnvironmentSays() throws {
        let lie = tempDirectory()
        let folder = lie + "/Library/Application Support/handsal-sign"
        try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(atPath: lie) }
        // Real P-256 points (G and 2G), so the whole signer path accepts the key if it ever reads it.
        let planted = StoredKey(label: "laptop", person: "mallory", keyClass: "apple-se-bio",
                                sign: Point(x: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY", y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"),
                                agree: Point(x: "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg", y: "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E"),
                                signBlob: [UInt8](repeating: 0xAA, count: 300), agreeBlob: [UInt8](repeating: 0xBB, count: 300))
        try Data(try KeyFile.encode(planted)).write(to: URL(fileURLWithPath: folder + "/key.json"))
        let kid = KeyMaterial(keyClass: planted.keyClass, person: planted.person, sign: planted.sign, agree: planted.agree).kid

        let draft = #"{"body":{"kid":"NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY","person":"carol"},"method":"local:handsal.device.remove","org":"\#(Encoding.emptyHash)","parent":{"id":"\#(Encoding.emptyHash)","performer":"bob"}}"#
        let process = Process()
        process.executableURL = ProcessTests.binary("handsal-sign")
        process.arguments = ["render"]
        process.environment = ["HOME": lie, "CFFIXED_USER_HOME": lie, "PATH": "/usr/bin:/bin"]
        let input = Pipe(), output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        input.fileHandleForWriting.write(Data(#"{"attachments":{},"draft":\#(draft)}"#.utf8))
        try input.fileHandleForWriting.close()
        let out = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()

        #expect(!out.contains("mallory"))
        #expect(!out.contains(kid))
        #expect(!out.contains(planted.sign.x))
        #expect(out.hasPrefix(#"{"error":"#) || out.hasPrefix(#"{"first_line":"#), "the signer answered: \(out)")
    }

    private struct SilentDisplay: Display { func show(_ text: String) throws {} }

    private func run(_ arguments: [String], _ stdin: String = "", backend: SecureEnclaveBackend) -> Outcome {
        let environment = Environment(backend: backend, display: { SilentDisplay() }, now: { 0 }, nonce: { Encoding.emptyHash },
                                      prompts: PromptGuard(lockPath: { try backend.lockPath() }, clock: { 0 }))
        return CLI.run(arguments: arguments, readStdin: { Array(stdin.utf8) }, environment: environment)
    }

    /// SH12: the key folder is resolved where a key is read, not at start-up. `version` and `emit` never read a key, so
    /// a uid with no home still answers them. Every command that does read one (`keygen`, `pubkey`, `render`, `sign`,
    /// `agree`) says `internal`, exit 5: that is the cause, and not `key_unavailable` for a key nobody looked for.
    @Test func aUidWithoutAHomeStillAnswersTheCommandsThatReadNoKey() {
        let noHome = SecureEnclaveBackend(home: { nil })
        let version = run(["version"], backend: noHome)
        #expect(version.exit == 0 && String(decoding: version.line, as: UTF8.self).contains(#""class":"apple-se-bio""#))

        let kid = "E5ua1p9OmQf5slKxgDSGQT1dJ-UuJ49b_T2ouEqyrrI"
        let draft = #"{"body":{"kid":"NAjtfK8uPx9mTY3cWuF1yDIJ4DUhiXDyS8-_7hYNraY","person":"carol"},"method":"local:handsal.device.remove","org":"\#(Encoding.emptyHash)","parent":{"id":"\#(Encoding.emptyHash)","performer":"bob"}}"#
        let emit = #"{"attachments":{},"draft":\#(draft),"fixed":{"kid":"\#(kid)","nonce":"\#(Encoding.emptyHash)","performer":"alice","ts":"2026-11-08T11:59:00Z"}}"#
        #expect(run(["emit"], emit, backend: noHome).exit == 0)

        let peer = #"{"x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}"#
        let commands: [(String, String)] = [
            ("keygen", #"{"label":"laptop","person":"alice"}"#),
            ("pubkey", ""),
            ("render", #"{"attachments":{},"draft":\#(draft)}"#),
            ("sign", #"{"attachments":{},"draft":\#(draft)}"#),
            ("agree", #"{"context":"acme","peer":\#(peer)}"#),
        ]
        for (name, input) in commands {
            let out = run([name], input, backend: noHome)
            #expect(out.exit == 5 && String(decoding: out.line, as: UTF8.self) == #"{"error":"internal"}"#, "\(name)")
        }
    }

    /// SH12: the prompt lock lives beside the key, so it is as fallible as the folder. With no home the lock path is
    /// `internal` (exit 5), there is no empty path to open, and the prompt never runs.
    @Test func theLockPathIsFallibleWhereTheFolderIsAndThePromptNeverRuns() {
        let noHome = SecureEnclaveBackend(home: { nil })
        #expect(throws: Refusal("internal")) { try noHome.lockPath() }
        let guardian = PromptGuard(lockPath: { try noHome.lockPath() }, clock: { 0 })
        var ran = false
        #expect(throws: Refusal("internal")) { try guardian.guarded { ran = true } }
        #expect(!ran, "no prompt runs without a lock")
        let withHome = SecureEnclaveBackend(home: { "/Users/acme" })
        #expect((try? withHome.lockPath()) == "/Users/acme/Library/Application Support/handsal-sign/prompt.lock")
    }

    /// S2, SH12: nothing under Sources reads the environment (or a call that follows it) for the home. The directory
    /// service is the only source. Comments are ignored; a planted call is the check that this scan can fail.
    @Test func noSourceReadsTheEnvironmentForTheHome() throws {
        let banned = ["getenv", "ProcessInfo", "NSHomeDirectory", "homeDirectoryForCurrentUser", "CFFIXED_USER_HOME", "\"HOME\"", "environ["]
        let sources = Vector.root.appendingPathComponent("signer/apple/Sources")
        let files = try #require(FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil))
        var seen = 0
        for case let url as URL in files where url.pathExtension == "swift" {
            seen += 1
            for (number, line) in try String(contentsOf: url, encoding: .utf8).split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
                let code = line.components(separatedBy: "//")[0]
                for word in banned where code.contains(word) {
                    Issue.record("\(url.lastPathComponent):\(number + 1) reads the environment for the home: \(word)")
                }
            }
        }
        #expect(seen > 20, "the scan found the sources")
    }

    /// SG-02: `version` names the class of the backend, and the backend is the one owner of that name. The name
    /// must be a class the registry holds, so a registry change that drops it fails here, not at a verifier.
    @Test func theShippedBackendNamesAClassTheRegistryHolds() {
        let backend = SecureEnclaveBackend(directory: tempDirectory())
        let held = Registry.standard.lookupClass(backend.keyClass, fixture: false)
        #expect(held != nil && held?.status == "active", "the shipped backend's class \(backend.keyClass)")
    }

    @Test func theKeyFileRoundTripsAndIsCanonicalSubset() throws {
        let key = stored()
        let bytes = try KeyFile.encode(key)
        #expect(try KeyFile.decode(bytes) == key)
        guard case .success = Subset.parse(bytes, maxSize: Limits.maxPayload) else { Issue.record("not in the canonical subset"); return }
        let other = stored(person: "bob", label: "phone")
        #expect(try KeyFile.decode(try KeyFile.encode(other)) == other)
        #expect(try KeyFile.encode(other) != bytes)
    }

    @Test func aDamagedKeyFileIsKeyUnavailable() throws {
        let good = try KeyFile.encode(stored())
        let text = String(decoding: good, as: UTF8.self)
        let damaged: [[UInt8]] = [
            [], Array("{}".utf8), Array("[]".utf8), Array(text.replacingOccurrences(of: "apple-se-bio", with: "").utf8),
            Array(text.replacingOccurrences(of: #""v":"1""#, with: #""v":"2""#).utf8),
            Array(text.replacingOccurrences(of: #""person":"alice""#, with: #""person":"A""#).utf8),
            Array(text.dropLast().utf8), good + [0x0A, 0x0A],
        ]
        for bytes in damaged {
            #expect(throws: Refusal("key_unavailable")) { try KeyFile.decode(bytes) }
        }
    }

    @Test func theFileIsCreatedPrivateAndNeverOverwritten() throws {
        let directory = tempDirectory()
        let path = directory + "/key.json"
        #expect(try KeyFile.read(path: path) == nil)
        try KeyFile.createExclusive(path: path, bytes: Array("first".utf8))
        #expect(try KeyFile.read(path: path) == Array("first".utf8))
        #expect(throws: Refusal("key_exists")) { try KeyFile.createExclusive(path: path, bytes: Array("second".utf8)) }
        #expect(try KeyFile.read(path: path) == Array("first".utf8))
        let file = try FileManager.default.attributesOfItem(atPath: path)
        let folder = try FileManager.default.attributesOfItem(atPath: directory)
        #expect((file[.posixPermissions] as? Int) == 0o600 && (folder[.posixPermissions] as? Int) == 0o700)
    }

    @Test func aSymlinkWhereTheKeyShouldBeIsNeverFollowed() throws {
        let directory = tempDirectory()
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        let target = directory + "/elsewhere"
        FileManager.default.createFile(atPath: target, contents: Data("planted".utf8))
        let path = directory + "/key.json"
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target)
        #expect(throws: Refusal("key_exists")) { try KeyFile.createExclusive(path: path, bytes: Array("mine".utf8)) }
        #expect(throws: Refusal("key_unavailable")) { _ = try KeyFile.read(path: path) }
        #expect(try String(contentsOfFile: target, encoding: .utf8) == "planted")
    }

    @Test func aBackendWithoutAKeyFileHoldsNoKey() throws {
        #expect(try SecureEnclaveBackend(directory: tempDirectory()).bound() == nil)
    }

    @Test func aBackendReadsTheKeyFileAsItsBoundKey() throws {
        let directory = tempDirectory()
        let key = stored(person: "carol")
        try KeyFile.createExclusive(path: directory + "/key.json", bytes: KeyFile.encode(key))
        let bound = try #require(try SecureEnclaveBackend(directory: directory).bound())
        #expect(bound == KeyMaterial(keyClass: "apple-se-bio", person: "carol", sign: key.sign, agree: key.agree))
    }

    // MARK: error mapping

    /// The errors below are the raw ones measured on a MacBook Air with a real Touch ID (T5.13,
    /// 2026-11-13), as the (domain, code) pair the platform gave, not as a Swift enum case.
    private static let laDomain = "com.apple.LocalAuthentication"
    private static let measuredLidClosed = NSError(domain: laDomain, code: -4)          // canEvaluatePolicy, lid closed
    private static let measuredFingerprintAdded = NSError(domain: "CryptoTokenKit", code: -3)  // sign after a fingerprint was added

    @Test func aPersonsCancelOrFailedVerificationIsUserCancel() {
        for code in [LAError.Code.userCancel, .userFallback, .authenticationFailed] {
            #expect(SecureEnclaveErrors.refusal(for: LAError(code)) == Refusal("user_cancel"), "\(code)")
        }
        for status in [-128, -25293] {
            #expect(SecureEnclaveErrors.refusal(for: NSError(domain: NSOSStatusErrorDomain, code: status)) == Refusal("user_cancel"), "\(status)")
        }
    }

    @Test func aSystemConditionIsNeverAPersonsCancel() {
        // measured: lid closed, canEvaluatePolicy false with LAError -4 (systemCancel)
        #expect(SecureEnclaveErrors.refusal(for: Self.measuredLidClosed) == Refusal("biometric_unavailable"))
        #expect(SecureEnclaveErrors.refusal(for: LAError(.systemCancel)) == Refusal("biometric_unavailable"))
        // biometryNotAvailable (-6): the sensor is off or unusable now (lid closed on other macOS versions, disabled);
        // it says nothing about the key, so it is never key_unavailable
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: Self.laDomain, code: -6)) == Refusal("biometric_unavailable"))
        #expect(SecureEnclaveErrors.refusal(for: LAError(.biometryNotAvailable)) == Refusal("biometric_unavailable"))
        // a locked-out sensor cannot verify now, whoever caused it
        #expect(SecureEnclaveErrors.refusal(for: LAError(.biometryLockout)) == Refusal("biometric_unavailable"))
        // appCancel and invalidContext are the signer's own context being invalidated: a signer fault, never a decision
        // and never a statement about the key
        #expect(SecureEnclaveErrors.refusal(for: LAError(.appCancel)) == Refusal("internal"))
        #expect(SecureEnclaveErrors.refusal(for: LAError(.invalidContext)) == Refusal("internal"))
    }

    @Test func aKeyThePlatformWillNotUseIsKeyUnavailable() {
        // no fingerprint enrolled or no passcode: a .biometryCurrentSet key is gone for good
        for code in [LAError.Code.biometryNotEnrolled, .passcodeNotSet] {
            #expect(SecureEnclaveErrors.refusal(for: LAError(code)) == Refusal("key_unavailable"), "\(code)")
        }
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: NSOSStatusErrorDomain, code: -25300)) == Refusal("key_unavailable"))
    }

    @Test func aKeyTheBiometricChangeInvalidatedIsKeyUnavailableByMeasuredValue() {
        // measured: after a fingerprint was added, the signature failed with CryptoTokenKit -3 (corruptedData)
        #expect(SecureEnclaveErrors.refusal(for: Self.measuredFingerprintAdded) == Refusal("key_unavailable"))
        // objectNotFound, the same key lost on restore
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: "CryptoTokenKit", code: -6)) == Refusal("key_unavailable"))
    }

    @Test func aCodeIsReadInItsOwnDomainOnly() {
        // -3 is userFallback in LocalAuthentication and corruptedData in CryptoTokenKit; -4 is systemCancel and canceledByUser.
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: Self.laDomain, code: -3)) == Refusal("user_cancel"))
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: "CryptoTokenKit", code: -3)) == Refusal("key_unavailable"))
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: "SomeOtherDomain", code: -3)) == Refusal("internal"))
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: NSOSStatusErrorDomain, code: -4)) == Refusal("internal"))
    }

    @Test func anythingElseIsInternalAndNeverACancel() {
        struct Strange: Error {}
        #expect(SecureEnclaveErrors.refusal(for: Strange()) == Refusal("internal"))
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: NSOSStatusErrorDomain, code: -50)) == Refusal("internal"))
        // an unmeasured CryptoTokenKit code is not guessed
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: "CryptoTokenKit", code: -4)) == Refusal("internal"))
        #expect(SecureEnclaveErrors.refusal(for: NSError(domain: "CryptoTokenKit", code: -99)) == Refusal("internal"))
    }

    // MARK: the precheck before the prompt (SG-08)

    private func backendWithKey(policy: BiometricPolicy) throws -> SecureEnclaveBackend {
        let directory = tempDirectory()
        try KeyFile.createExclusive(path: directory + "/key.json", bytes: KeyFile.encode(stored()))
        return SecureEnclaveBackend(directory: directory, policy: policy)
    }

    @Test func aSensorThatCannotVerifyNowIsRefusedBeforeAnyPrompt() throws {
        let closed = try backendWithKey(policy: BiometricPolicy { Self.measuredLidClosed })
        #expect(throws: Refusal("biometric_unavailable")) { try closed.ready() }
        let off = try backendWithKey(policy: BiometricPolicy { NSError(domain: Self.laDomain, code: -6) })
        #expect(throws: Refusal("biometric_unavailable")) { try off.ready() }
        let notEnrolled = try backendWithKey(policy: BiometricPolicy { LAError(.biometryNotEnrolled) })
        #expect(throws: Refusal("key_unavailable")) { try notEnrolled.ready() }
        let strange = try backendWithKey(policy: BiometricPolicy { NSError(domain: "Nowhere", code: 1) })
        #expect(throws: Refusal("internal")) { try strange.ready() }
    }

    @Test func aSensorThatCanVerifyPassesTheCheck() throws {
        try backendWithKey(policy: BiometricPolicy { nil }).ready()
    }

    @Test func theLivePolicyAsksThePlatformWithAFreshContextEachTime() throws {
        // On a machine with no usable sensor this is a refusal, with one it is nil: both are answers, neither is a crash.
        let first = BiometricPolicy.live.unavailability(), second = BiometricPolicy.live.unavailability()
        #expect((first == nil) == (second == nil))
        if let failure = first { #expect(SecureEnclaveErrors.refusal(for: failure).code != "user_cancel") }
    }

    // MARK: no authentication context outlives a signature (SG-05)

    /// SG-05 asks for a new `LAContext` per signature and none accepted from a caller. The type
    /// level answer: the context is a local of `sign`, never a property, a parameter or a result,
    /// so no call can hand one in and none can survive the call. This reads the source and fails
    /// the day a line breaks that shape.
    @Test func noLAContextCrossesACallBoundary() throws {
        let source = try String(contentsOf: Vector.root.appendingPathComponent("signer/apple/Sources/HandsalSecureEnclave/SecureEnclaveBackend.swift"), encoding: .utf8)
        let lines = source.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let uses = lines.filter { $0.contains("LAContext") }
        #expect(!uses.isEmpty)
        for use in uses {
            #expect(use.trimmingCharacters(in: .whitespaces) == "let context = LAContext()", "\(use)")
            #expect(use.prefix(while: { $0 == " " }).count >= 8, "a context is created inside a method body: \(use)")
        }
        #expect(uses.count == 1)
        #expect(source.contains("context.localizedReason = reason"))
        // the only place a context is passed on is the key it is created for
        #expect(source.components(separatedBy: "authenticationContext: context").count == 2)
        #expect(!source.contains("var context") && !source.contains("static let context"))
    }

    /// The precheck asks the platform with a context of its own, made inside the call and dropped
    /// with it: no policy object keeps one between signatures either.
    @Test func thePolicyCheckKeepsNoContext() throws {
        let source = try String(contentsOf: Vector.root.appendingPathComponent("signer/apple/Sources/HandsalSecureEnclave/BiometricPolicy.swift"), encoding: .utf8)
        let uses = source.split(separator: "\n").map(String.init).filter { $0.contains("LAContext()") }
        #expect(uses.count == 1)
        for use in uses { #expect(use.trimmingCharacters(in: .whitespaces) == "let context = LAContext()", "\(use)") }
        #expect(!source.contains("var context") && !source.contains("static let context"))
    }

    // MARK: the agreement key needs no presence (SG-16, KC-09)

    private final class Count: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        func hit() { lock.withLock { n += 1 } }
        var value: Int { lock.withLock { n } }
    }

    /// On this machine's Secure Enclave: a real agreement key, created without presence, derives a key with no finger,
    /// no context and no policy question, and a peer that holds a software key derives the same bytes. The
    /// test runs unattended, so a key that needed a touch would fail it. Without a Secure Enclave there is nothing to measure.
    @Test(.enabled(if: SecureEnclave.isAvailable))
    func theSecureEnclaveAgreementKeyWorksWithNoPresence() throws {
        let asked = Count()
        let backend = SecureEnclaveBackend(directory: tempDirectory(), policy: BiometricPolicy { asked.hit(); return nil })
        let made = try backend.create(label: "laptop", person: "alice") { _ in }
        #expect(made.sign != made.agree)
        let peer = P256.KeyAgreement.PrivateKey()
        let raw = [UInt8](peer.publicKey.x963Representation)
        let point = Point(x: Encoding.base64url(Array(raw[1..<33])), y: Encoding.base64url(Array(raw[33..<65])))
        let info = try #require(Agreement.info(own: made.agree, peer: point, context: "mail/v1"))
        let derived = try backend.agree(peer: point, info: info)
        #expect(derived.count == 32)
        let x = try #require(Encoding.base64urlDecode(made.agree.x)), y = try #require(Encoding.base64urlDecode(made.agree.y))
        let device = try P256.KeyAgreement.PublicKey(x963Representation: Data([0x04] + x + y))
        #expect(derived == Agreement.key(from: try peer.sharedSecretFromKeyAgreement(with: device), info: info))
        #expect(asked.value == 0, "no policy question: nothing is asked of a person")
        // again, and for another peer: still no question
        let other = P256.KeyAgreement.PrivateKey()
        let otherRaw = [UInt8](other.publicKey.x963Representation)
        let otherPoint = Point(x: Encoding.base64url(Array(otherRaw[1..<33])), y: Encoding.base64url(Array(otherRaw[33..<65])))
        #expect(try backend.agree(peer: otherPoint, info: info) != derived && asked.value == 0)
    }
}
