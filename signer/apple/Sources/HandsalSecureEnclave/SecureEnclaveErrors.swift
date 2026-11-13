import Foundation
import HandsalCore

/// What the platform said to a signature request, as the signer's codes (SG-08).
///
/// The mapping is a table keyed by (domain, code), the pair the platform reports, because a code
/// number means different things in different domains (-3 is `userFallback` in LocalAuthentication
/// and `corruptedData` in CryptoTokenKit). Every row is a value read from a real platform or from
/// its documented constants; a pair that is not in the table is `internal`, never a guess.
///
/// - `user_cancel` (exit 1): the person decided or failed: cancel, fallback, a failed verification.
/// - `biometric_unavailable` (exit 4): the platform could not ask now (lid closed, sensor locked
///   out, the system interrupted the prompt). That is a condition, not a decision of the person.
/// - `key_unavailable` (exit 3): this key will never sign again (no biometrics enrolled, no
///   passcode, a key a change of the enrolled set invalidated, a missing item). Recovery is
///   `device.add` from other devices (SG-11). A code that says nothing about the key is not here:
///   `biometryNotAvailable` (sensor off or unusable now) is `biometric_unavailable`.
/// - `appCancel` and `invalidContext` are not in the table: the signer never invalidates its own
///   context, so either would be a fault of the signer, which is `internal`.
///
/// Measured on a MacBook Air, T5.13: LocalAuthentication -4 from `canEvaluatePolicy` with the lid
/// closed; CryptoTokenKit -3 (`corruptedData`) when signing after a fingerprint was added.
public enum SecureEnclaveErrors {
    private struct Platform: Hashable {
        let domain: String
        let code: Int
    }

    private static let localAuthentication = "com.apple.LocalAuthentication"
    private static let cryptoTokenKit = "CryptoTokenKit"

    private static let table: [Platform: String] = {
        var rows: [Platform: String] = [:]
        func add(_ domain: String, _ codes: [Int], _ code: String) { for number in codes { rows[Platform(domain: domain, code: number)] = code } }
        // LAError: authenticationFailed, userCancel, userFallback
        add(localAuthentication, [-1, -2, -3], "user_cancel")
        // LAError: systemCancel (measured, lid closed), biometryNotAvailable, biometryLockout
        add(localAuthentication, [-4, -6, -8], "biometric_unavailable")
        // LAError: passcodeNotSet, biometryNotEnrolled (a .biometryCurrentSet key is gone for good)
        add(localAuthentication, [-5, -7], "key_unavailable")
        // errSecUserCanceled, errSecAuthFailed
        add(NSOSStatusErrorDomain, [-128, -25293], "user_cancel")
        // errSecItemNotFound
        add(NSOSStatusErrorDomain, [-25300], "key_unavailable")
        // TKError: corruptedData (measured, fingerprint added), objectNotFound
        add(cryptoTokenKit, [-3, -6], "key_unavailable")
        return rows
    }()

    public static func refusal(for error: Error) -> Refusal {
        let platform = error as NSError
        return Refusal(table[Platform(domain: platform.domain, code: platform.code)] ?? "internal")
    }
}
