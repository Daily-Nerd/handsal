import CryptoKit
import Foundation
import HandsalCore
import Testing

/// KC-07, SG-03: what the signer needs of a key backend, run on the software backend. The same
/// contract is what the hardware backend has to satisfy; its Touch ID parts are a manual list.
@Suite("key backend contract (KC-07, SG-03)")
struct KeyBackendContractTests {
    @Test func aFreshBackendHoldsNoKey() throws {
        let backend = SoftwareBackend()
        #expect(try backend.bound() == nil)
        #expect(backend.keyClass == "test-sw-p256")
    }

    @Test func createBindsThePersonAndTheClassAndReturnsBothPublicKeys() throws {
        let backend = SoftwareBackend()
        let made = try backend.create(label: "laptop", person: "alice") { _ in }
        #expect(made.person == "alice" && made.keyClass == "test-sw-p256" && made.kid == Encoding.thumbprint(x: made.sign.x, y: made.sign.y))
        #expect(try backend.bound() == made)
        #expect(made.sign != made.agree)
        let other = try SoftwareBackend(keyClass: "apple-se-bio").create(label: "phone", person: "bob") { _ in }
        #expect(other.person == "bob" && other.keyClass == "apple-se-bio" && other.kid != made.kid)
    }

    @Test func aRefusingAcceptStoresNothing() throws {
        let backend = SoftwareBackend()
        #expect(throws: Refusal("internal")) { try backend.create(label: "laptop", person: "alice") { _ in throw Refusal("internal") } }
        #expect(try backend.bound() == nil)
        _ = try backend.create(label: "laptop", person: "alice") { _ in }
        #expect(try backend.bound() != nil)
    }

    @Test func aSecondCreateIsKeyExistsAndKeepsTheFirst() throws {
        let backend = SoftwareBackend()
        let first = try backend.create(label: "laptop", person: "alice") { _ in }
        #expect(throws: Refusal("key_exists")) { try backend.create(label: "again", person: "bob") { _ in } }
        #expect(try backend.bound() == first)
    }

    @Test func signsTheMessageItIsGivenUnderTheSignKey() throws {
        let backend = SoftwareBackend()
        let made = try backend.create(label: "laptop", person: "alice") { _ in }
        for message in [Array("one".utf8), Array("a much longer message for the second signature".utf8)] {
            let raw = try backend.sign(message, reason: "why")
            #expect(raw.count == 64)
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(raw))
            #expect(try publicKey(made).isValidSignature(signature, for: Data(message)))
        }
        #expect(backend.prompts == ["why", "why"])
    }
}

/// T5.10: the shipped signer has no path to the software backend, and the software backend is the
/// only thing the tests use in place of hardware.
@Suite("software backend stays in the tests (T5.10)")
struct BackendLinkTests {
    private func contains(_ file: String, _ needle: String) throws -> Bool {
        try Data(contentsOf: ProcessTests.binary(file)).range(of: Data(needle.utf8)) != nil
    }

    @Test func theShippedBinariesHoldNoSoftwareBackend() throws {
        for file in ["handsal-sign", "handsal-sign-conformance"] {
            #expect(try !contains(file, "SoftwareBackend"), "\(file)")
            #expect(try !contains(file, "RecordingDisplay"), "\(file)")
        }
    }

    @Test func theShippedSignerHoldsTheHardwareBackendAndTheConformanceExecutableDoesNot() throws {
        #expect(try contains("handsal-sign", "SecureEnclaveBackend"))
        #expect(try !contains("handsal-sign-conformance", "SecureEnclaveBackend"))
    }
}
