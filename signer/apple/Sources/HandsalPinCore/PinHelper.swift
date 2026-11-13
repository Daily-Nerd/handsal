import Darwin
import HandsalCore

/// The macOS pin helper (GP-12, GP-21, SG-14): the one writer of the pin.
///
/// Per org the pin only moves forward along one lineage, only to a lineage whose every link is
/// authorized, only at the path of the org it names, only with bytes and attributes the reader
/// accepts, and one run at a time. The steps, first failure wins and no pin written on any failure:
///   input    no argument; one `{acts, lineage}` line  (`malformed_input`, `unparseable_input`)
///   0        check or create the directories, take the lock           (`pin_owner`, `internal`)
///   1        run the production checker's `genesis-check`; unless `valid:true`, `pin_invalid`;
///            the returned `pin` is the only content ever written
///   2        derive the path from that pin's `org` only
///   3        a file at that path must be a well-formed pin for that org (`pin_malformed`) and the new
///            lineage must contain the document whose hash is its `genesis` (`pin_rollback`)
///   write    temporary file, attributes, flush, rename, sync
///
/// Why this shape: the writer enforces the reader's invariant (GP-10), so the ownership rules have
/// one owner; there is no repair, no delete and no argument, so there is no second source for the
/// org and no path that moves a pin back.
///
/// Test constructor: `init(checker:root:owner:)` stands in for the SG-14 checker path, the GP-10
/// root and root:wheel. It exists only in a debug build, so a release build, the one that is
/// installed, has no such constructor at all, and only a test built with `@testable` can call it.
/// The installed binary calls `installed()`, which has none of those parameters and reads no
/// environment, so a caller cannot reach it by an argument, a variable or an input key (GP-14).
public struct PinHelper: Sendable {
    let checker: CheckerCommand
    let directories: PinDirectories

    var owner: Owner { directories.owner }

    private init(checker: CheckerCommand, directories: PinDirectories) {
        self.checker = checker
        self.directories = directories
    }

    #if DEBUG
    init(checker: CheckerCommand, root: String, owner: Owner) {
        self.init(checker: checker, directories: PinDirectories(root: root, owner: owner))
    }
    #endif

    public static func installed() -> PinHelper {
        PinHelper(checker: .installed, directories: PinDirectories(root: "/", owner: .administrator))
    }

    public func run(arguments: [String], stdin: [UInt8]) -> PinReport {
        signal(SIGPIPE, SIG_IGN)   // a checker that exits early must not kill the helper mid-write
        do {
            return try perform(PinRequest.read(arguments: arguments, stdin: stdin))
        } catch let failure as PinFailure {
            return PinReport(reason: failure.reason, inner: failure.inner)
        } catch {
            return PinReport(reason: .internal)
        }
    }

    private func perform(_ request: PinRequest) throws -> PinReport {
        try directories.ensure()
        let lock = try PinLock.take(at: directories.lock, owner: owner)
        defer { lock.release() }

        let answer = try CheckerAnswer.run(checker, input: request.object)
        guard answer.valid, let pin = answer.pin, let line = PinLine.parse(pin) else {
            throw PinFailure(.pinInvalid, inner: answer.reason)
        }
        // From here the checker has answered, so every failure carries its reason as `inner_reason`.
        do {
            let store = PinStore(directories: directories, owner: owner)
            if let current = try store.existing(org: line.org) {
                guard try request.lineage.contains(where: { try Self.documentHash($0) == current.genesis }) else {
                    throw PinFailure(.pinRollback)
                }
            }
            try store.write(pin, org: line.org)
        } catch let failure as PinFailure {
            throw PinFailure(failure.reason, inner: answer.reason)
        }
        return PinReport(reason: .ok, inner: answer.reason, written: true)
    }

    /// The hash of the `doc` of a lineage entry. The checker has judged the lineage valid, so an entry
    /// without a document that hashes is not a case to skip: it is a disagreement, and `internal`.
    private static func documentHash(_ entry: JValue) throws -> String {
        guard let document = entry["doc"], let hash = try? Genesis.docHash(document) else { throw PinFailure(.internal) }
        return hash
    }
}
