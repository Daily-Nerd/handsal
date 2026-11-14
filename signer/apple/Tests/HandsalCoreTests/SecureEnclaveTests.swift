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
        #expect(SecureEnclaveBackend.defaultDirectory.hasSuffix("/Library/Application Support/handsal-sign"))
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
}
