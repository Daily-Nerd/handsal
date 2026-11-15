import Foundation
import HandsalCore
import Testing

private func tempLock() -> String { NSTemporaryDirectory() + "handsal-guard-\(UUID().uuidString).lock" }

/// SG-10: limit prompt frequency per process, and never run while another of its prompts is open.
@Suite("prompt guard (SG-10)")
struct PromptGuardTests {
    @Test func aSecondPromptWhileOneIsOpenIsRefused() throws {
        let path = tempLock()
        let first = PromptGuard(lockPath: path, maxPrompts: 100, perSeconds: 60, clock: { 0 })
        let second = PromptGuard(lockPath: path, maxPrompts: 100, perSeconds: 60, clock: { 0 })
        var ran = 0
        let value: Int = try first.guarded {
            #expect(throws: Refusal("prompt_refused")) { try second.guarded { ran += 1; return 0 } }
            return 7
        }
        #expect(value == 7 && ran == 0)
        // once the first prompt is closed the lock is free again, for either guard
        #expect(try second.guarded { ran += 1; return 1 } == 1 && ran == 1)
        #expect(try first.guarded { ran += 1; return 2 } == 2 && ran == 2)
    }

    @Test func theSameGuardIsNotReentrant() throws {
        let guardian = PromptGuard(lockPath: tempLock(), maxPrompts: 100, perSeconds: 60, clock: { 0 })
        _ = try guardian.guarded {
            #expect(throws: Refusal("prompt_refused")) { try guardian.guarded { 0 } }
        }
    }

    @Test func aFailingPromptReleasesTheLock() throws {
        let guardian = PromptGuard(lockPath: tempLock(), maxPrompts: 100, perSeconds: 60, clock: { 0 })
        #expect(throws: Refusal("user_cancel")) { try guardian.guarded { throw Refusal("user_cancel") } }
        #expect(try guardian.guarded { 3 } == 3)
    }

    @Test func promptsAreRateLimitedPerProcess() throws {
        let clock = Counter(0)
        let guardian = PromptGuard(lockPath: tempLock(), maxPrompts: 3, perSeconds: 60, clock: { clock.value })
        for _ in 0..<3 { #expect(try guardian.guarded { 1 } == 1) }
        var ran = false
        #expect(throws: Refusal("prompt_refused")) { try guardian.guarded { ran = true; return 1 } }
        #expect(!ran)
        clock.value = 59
        #expect(throws: Refusal("prompt_refused")) { try guardian.guarded { 1 } }
        clock.value = 61
        #expect(try guardian.guarded { 1 } == 1)
    }

    @Test func aRefusedPromptDoesNotCountAgainstTheLimit() throws {
        let clock = Counter(0)
        let path = tempLock()
        let guardian = PromptGuard(lockPath: path, maxPrompts: 2, perSeconds: 60, clock: { clock.value })
        #expect(try guardian.guarded { 1 } == 1)
        let rival = PromptGuard(lockPath: path, maxPrompts: 100, perSeconds: 60, clock: { 0 })
        _ = try rival.guarded {
            #expect(throws: Refusal("prompt_refused")) { try guardian.guarded { 1 } }   // busy, not counted
        }
        #expect(try guardian.guarded { 1 } == 1)
    }

    @Test func aLockFileThatCannotBeOpenedIsInternal() {
        let guardian = PromptGuard(lockPath: "/nonexistent-directory/handsal.lock", maxPrompts: 5, perSeconds: 60, clock: { 0 })
        #expect(throws: Refusal("internal")) { try guardian.guarded { 1 } }
    }

    @Test func theLockFileIsPrivate() throws {
        let path = tempLock()
        let guardian = PromptGuard(lockPath: path, maxPrompts: 5, perSeconds: 60, clock: { 0 })
        _ = try guardian.guarded { 1 }
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        #expect((attributes[.posixPermissions] as? Int) == 0o600)
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Int
    init(_ start: Int) { current = start }
    var value: Int {
        get { lock.withLock { current } }
        set { lock.withLock { current = newValue } }
    }
}
