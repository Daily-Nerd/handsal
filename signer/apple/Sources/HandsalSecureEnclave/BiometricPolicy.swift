import Foundation
import LocalAuthentication

/// Whether the biometric sensor can verify a person right now, asked before any prompt (SG-08).
///
/// Owner of the one question "can the platform ask for a fingerprint now?". The answer is nil, or
/// the platform's own error, which `SecureEnclaveErrors` maps. The live policy asks with a context
/// made inside the call and dropped with it, so nothing survives from one signature to the next
/// (SG-05). A test builds its own from a closure, so no test needs a finger or an open lid.
public struct BiometricPolicy: Sendable {
    private let check: @Sendable () -> Error?

    public init(_ check: @escaping @Sendable () -> Error?) { self.check = check }

    /// nil when the sensor can verify now, else why it cannot.
    public func unavailability() -> Error? { check() }

    public static let live = BiometricPolicy {
        let context = LAContext()
        var failure: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &failure) { return nil }
        // no reason given is no reason known: it maps to internal, never to a guess
        return failure ?? NSError(domain: "handsal.biometric-policy", code: 0)
    }
}
