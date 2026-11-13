import Foundation
import HandsalCore
import LocalAuthentication

/// What the platform said to a signature request, as the signer's codes (SG-08).
///
/// A cancelled prompt and a failed or locked-out verification are `user_cancel` (exit 1): the
/// person did not authorize this signature. A key the platform will not use (no biometrics
/// enrolled, no passcode, a key invalidated by a change of the enrolled set, a missing item) is
/// `key_unavailable` (exit 3, recovery is `device.add` from other devices, SG-11). Anything not
/// listed is `internal`: an error nobody mapped must never read as a cancel.
public enum SecureEnclaveErrors {
    private static let cancelled: Set<LAError.Code> = [.userCancel, .appCancel, .systemCancel, .userFallback, .authenticationFailed, .biometryLockout]
    private static let unusable: Set<LAError.Code> = [.biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet, .invalidContext]
    // errSecUserCanceled, errSecAuthFailed; errSecItemNotFound
    private static let statusCancelled: Set<Int> = [-128, -25293]
    private static let statusUnusable: Set<Int> = [-25300]

    public static func refusal(for error: Error) -> Refusal {
        if let failure = error as? LAError {
            if cancelled.contains(failure.code) { return Refusal("user_cancel") }
            if unusable.contains(failure.code) { return Refusal("key_unavailable") }
            return Refusal("internal")
        }
        let status = error as NSError
        if status.domain == NSOSStatusErrorDomain {
            if statusCancelled.contains(status.code) { return Refusal("user_cancel") }
            if statusUnusable.contains(status.code) { return Refusal("key_unavailable") }
        }
        return Refusal("internal")
    }
}
