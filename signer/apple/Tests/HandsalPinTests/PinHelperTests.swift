import CryptoKit
import Darwin
import Foundation
import HandsalCore
import HandsalKeyScan
import Testing
@testable import HandsalPinCore

private let org = PinRig.hashstr("org")
private let genesisA = PinRig.documentHash(named: "a")
private let genesisB = PinRig.documentHash(named: "b")
private func valid(_ genesis: String, org: String = org) -> String { PinRig.validAnswer(pin: PinRig.pin(org: org, genesis: genesis)) }

/// GP-21 and the CF-07 list for the pin helper, one test per item, against the library build: the
/// stub checker stands for the production checker at its SG-14 path and a temporary tree for `/`.
@Suite("pin helper (GP-21, GP-12)")
struct PinHelperTests {
    // MARK: Input

    @Test("sgn/pin-helper-argument-refused: any argument is malformed_input and nothing is written")
    func anArgumentIsRefused() throws {
        let rig = try PinRig()
        let report = try rig.helper(answering: valid(genesisA)).run(arguments: ["--org", "x"], stdin: PinRig.request(names: ["a"]))
        #expect(report == PinReport(reason: .malformedInput) && report.exit == 2)
        #expect(text(report) == #"{"inner_reason":null,"reason":"malformed_input","written":"no"}"#)
        #expect(rig.entries().isEmpty && !FileManager.default.fileExists(atPath: rig.seen))
    }

    @Test("sgn/pin-helper-third-key-refused: a missing, extra or mistyped key is malformed_input")
    func theKeysAreExactlyActsAndLineage() throws {
        let rig = try PinRig()
        let helper = try rig.helper(answering: valid(genesisA))
        for body in [#"{"acts":[]}"#, #"{"lineage":[]}"#, #"{"acts":[],"lineage":[],"pin_line":"x"}"#, #"{"acts":{},"lineage":[]}"#,
                     #"{"acts":[],"lineage":"x"}"#, #"{"acts":[],"lineage":null}"#, #"{"acts":"x","lineage":{}}"#, "[]", "null", #""x""#, "{}"] {
            let report = helper.run(arguments: [], stdin: Array((body + "\n").utf8))
            #expect(report == PinReport(reason: .malformedInput), "\(body)")
        }
        #expect(rig.entries().isEmpty && !FileManager.default.fileExists(atPath: rig.seen), "the checker was never run")
    }

    @Test("sgn/pin-helper-unparseable-input: a duplicate key, no LF, bytes after the LF, a second LF, over MAX_INPUT")
    func theRecognizerDecidesTheFraming() throws {
        let rig = try PinRig()
        let helper = try rig.helper(answering: valid(genesisA))
        let good = #"{"acts":[],"lineage":[]}"#
        let cases: [[UInt8]] = [
            Array(#"{"acts":[],"acts":[],"lineage":[]}"#.utf8) + [0x0A],
            Array(good.utf8),                                     // no closing LF
            Array((good + "\n" + good + "\n").utf8),              // bytes after the LF
            Array((good + "\n\n").utf8),                          // a second LF
            Array((good + "\r\n").utf8),                          // CRLF
            Array(#"{"acts":[],"lineage":[],}"#.utf8) + [0x0A],   // not the subset
            Array(#"{"lineage":[],"acts":[]}"#.utf8) + [0x0A],    // unsorted keys
            [UInt8](repeating: 0x20, count: Limits.maxInput + 1),
            [],
        ]
        for input in cases {
            let report = helper.run(arguments: [], stdin: input)
            #expect(report == PinReport(reason: .unparseableInput) && report.exit == 2, "\(input.prefix(30))")
        }
        #expect(rig.entries().isEmpty)
    }

    @Test("an argument is judged before the input, and the input before any directory is made")
    func inputFailuresComeBeforeStepZero() throws {
        let rig = try PinRig(withHandsalDirectory: false)
        let helper = try rig.helper(answering: valid(genesisA))
        #expect(helper.run(arguments: ["x"], stdin: []) == PinReport(reason: .malformedInput))
        #expect(helper.run(arguments: [], stdin: Array("{}".utf8)) == PinReport(reason: .unparseableInput))
        #expect(!FileManager.default.fileExists(atPath: rig.handsal))
    }

    // MARK: Steps 1 to 3 and the write

    @Test("sgn/pin-helper-first-pin: a first pin is written, with the checker's bytes and the reader's attributes")
    func aFirstPinIsWritten() throws {
        let rig = try PinRig()
        let pin = PinRig.pin(org: org, genesis: genesisA)
        let report = try rig.helper(answering: PinRig.validAnswer(pin: pin)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report == PinReport(reason: .ok, inner: "ok", written: true) && report.exit == 0)
        #expect(text(report) == #"{"inner_reason":"ok","reason":"ok","written":"yes"}"#)
        #expect(rig.contents(org: org) == pin)
        let info = rig.attributes(rig.pinPath(org: org))
        #expect(info.st_mode & 0o7777 == 0o644 && info.st_nlink == 1 && info.st_uid == getuid() && info.st_gid == getgid())
        #expect(rig.entries() == [PinLine.fileName(org: org)!], "no temporary file is left")
    }

    @Test("SG-03: neither the report nor a file the helper writes carries the private scalar of a key on the machine")
    func noOutputCarriesKeyMaterial() throws {
        let scalar = [UInt8](P256.Signing.PrivateKey().rawRepresentation)
        let rig = try PinRig()
        let pin = PinRig.pin(org: org, genesis: genesisA)
        let report = try rig.helper(answering: PinRig.validAnswer(pin: pin)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report.exit == 0)
        let written = try Data(contentsOf: URL(fileURLWithPath: rig.pinPath(org: org)))
        let seen = report.line + [UInt8](written) + Array(rig.entries().joined(separator: "\n").utf8)
        // the scan ran over real output: the pin's genesis is in the file and the reason in the report
        #expect(KeyScan.contains(seen, Array(genesisA.utf8)) && KeyScan.contains(seen, Array("\"reason\":\"ok\"".utf8)))
        #expect(!KeyScan.leaks(seen, scalar: scalar))
    }

    @Test("sgn/pin-helper-extension-written: a pin moves forward along one lineage")
    func anExtensionIsWritten() throws {
        let rig = try PinRig()
        try rig.place(PinRig.pin(org: org, genesis: genesisA), org: org)
        let next = PinRig.pin(org: org, genesis: genesisB)
        let report = try rig.helper(answering: PinRig.validAnswer(pin: next)).run(arguments: [], stdin: PinRig.request(names: ["a", "b"]))
        #expect(report == PinReport(reason: .ok, inner: "ok", written: true))
        #expect(rig.contents(org: org) == next)
        #expect(rig.entries().count == 1)
        // the same pin again: the lineage contains the pin's own genesis, so it is a no-op rewrite
        #expect(try rig.helper(answering: PinRig.validAnswer(pin: next)).run(arguments: [], stdin: PinRig.request(names: ["a", "b"])).reason == .ok)
    }

    @Test("sgn/pin-helper-rollback-refused: a pin on epoch 1 and a ceremony submitting epoch 0, the file unchanged")
    func aRollbackIsRefused() throws {
        let rig = try PinRig()
        let current = PinRig.pin(org: org, genesis: genesisB)
        try rig.place(current, org: org)
        let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report == PinReport(reason: .pinRollback, inner: "ok") && report.exit == 3)
        #expect(text(report) == #"{"inner_reason":"ok","reason":"pin_rollback","written":"no"}"#)
        #expect(rig.contents(org: org) == current && rig.entries().count == 1)
    }

    @Test("sgn/pin-helper-sibling-change-refused: a pin on a sibling change is not in the new lineage")
    func aSiblingChangeIsARollback() throws {
        let rig = try PinRig()
        let sibling = PinRig.pin(org: org, genesis: PinRig.documentHash(named: "sibling"))
        try rig.place(sibling, org: org)
        // epoch 0 `a`, then a change `b` that is not the sibling the machine is pinned to
        let report = try rig.helper(answering: valid(genesisB)).run(arguments: [], stdin: PinRig.request(names: ["a", "b"]))
        #expect(report.reason == .pinRollback)
        #expect(rig.contents(org: org) == sibling)
    }

    @Test("sgn/pin-helper-invalid-lineage-refused: not valid:true is pin_invalid with the checker's reason, nothing written")
    func anInvalidLineageIsRefused() throws {
        let rig = try PinRig()
        let report = try rig.helper(answering: PinRig.invalidAnswer("genesis_head_unknown")).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report == PinReport(reason: .pinInvalid, inner: "genesis_head_unknown") && report.exit == 3)
        #expect(text(report) == #"{"inner_reason":"genesis_head_unknown","reason":"pin_invalid","written":"no"}"#)
        #expect(rig.entries().isEmpty)
        // an `{"error"}` answer is not valid:true either
        let refused = try rig.helper(answering: #"{"error":"malformed_input"}"#).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(refused == PinReport(reason: .pinInvalid, inner: "malformed_input"))
    }

    @Test("sgn/pin-helper-path-from-returned-org: the path comes from the org of the returned line only")
    func theOrgIsTheCheckersAndNobodyElses() throws {
        let rig = try PinRig()
        let other = PinRig.hashstr("another org")
        let otherPin = PinRig.pin(org: other, genesis: genesisA)
        try rig.place(otherPin, org: other)
        let before = rig.attributes(rig.pinPath(org: other))
        // the input names no org at all; the returned line says `org`, so that is the file written
        let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report.reason == .ok)
        #expect(rig.contents(org: org) == PinRig.pin(org: org, genesis: genesisA))
        #expect(rig.contents(org: other) == otherPin, "another org's file is untouched")
        let after = rig.attributes(rig.pinPath(org: other))
        #expect(before.st_ino == after.st_ino && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec)
        #expect(rig.entries().count == 2)
    }

    @Test("sgn/pin-helper-malformed-file-refused: a malformed file at the derived path is pin_malformed and stays")
    func aMalformedFileAtThePathIsRefused() throws {
        let sound = PinRig.pin(org: org, genesis: genesisA)
        let anotherOrg = PinRig.pin(org: PinRig.hashstr("elsewhere"), genesis: genesisA)
        let bad: [String] = [
            "", "x", sound.replacingOccurrences(of: "\n", with: "\r\n"), sound + sound, String(sound.dropLast()),
            sound.replacingOccurrences(of: #""v":"handsal-pin/1""#, with: #""v":"handsal-pin/2""#),
            anotherOrg,                                     // well formed, for another org
            sound.replacingOccurrences(of: "{", with: "{ "), // whitespace
            String(repeating: "a", count: 513),
        ]
        for content in bad {
            let rig = try PinRig()
            try rig.place(content, org: org)
            let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
            #expect(report == PinReport(reason: .pinMalformed, inner: "ok") && report.exit == 3, "\(content.prefix(40))")
            #expect(rig.contents(org: org) == content)
        }
    }

    @Test("a directory or a symlink at the derived path is pin_malformed, never followed")
    func aNonRegularEntryAtThePathIsRefused() throws {
        let rig = try PinRig()
        try PinRig.directory(rig.pinPath(org: org), 0o755)
        #expect(try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"])).reason == .pinMalformed)
        let linked = try PinRig()
        try linked.place(PinRig.pin(org: org, genesis: genesisA), org: PinRig.hashstr("target"))
        symlink(linked.pinPath(org: PinRig.hashstr("target")), linked.pinPath(org: org))
        #expect(try linked.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"])).reason == .pinMalformed)
    }

    // MARK: Directories

    @Test("sgn/pin-helper-creates-directories: absent `handsal` and `orgs` are made with the reader's attributes, whatever the umask")
    func absentDirectoriesAreCreated() throws {
        let rig = try PinRig(withHandsalDirectory: false)
        let old = umask(0o077)
        defer { umask(old) }
        let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report.reason == .ok)
        for path in [rig.handsal, rig.orgs] {
            let info = rig.attributes(path)
            #expect(info.st_mode & S_IFMT == S_IFDIR && info.st_mode & 0o7777 == 0o755 && info.st_uid == getuid() && info.st_gid == getgid(), "\(path)")
        }
        let lock = rig.attributes(rig.handsal + "/pin.lock")
        #expect(lock.st_mode & S_IFMT == S_IFREG && lock.st_mode & 0o7777 == 0o644 && lock.st_nlink == 1)
        #expect(rig.attributes(rig.pinPath(org: org)).st_mode & 0o7777 == 0o644)
    }

    @Test("sgn/pin-helper-existing-dir-wrong-owner-refused: an existing directory the reader would reject is pin_owner, nothing written")
    func anExistingDirectoryTheReaderRejectsIsRefused() throws {
        // the owner the helper treats as administrator is someone else
        let stranger = Owner(uid: getuid() &+ 1, gid: getgid())
        let rig = try PinRig(owner: stranger)
        let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report == PinReport(reason: .pinOwner) && report.exit == 3)
        #expect(rig.entries().isEmpty && !FileManager.default.fileExists(atPath: rig.seen))
    }

    @Test("a directory writable by group or others, a symlink and a file in place of a directory are pin_owner, at any level")
    func everyDirectoryOfTheChainIsChecked() throws {
        let levels: [(String, (PinRig) -> String)] = [("root", { $0.root }), ("Library", { $0.root + "/Library" }),
                                                        ("Application Support", { $0.root + "/Library/Application Support" }),
                                                        ("handsal", { $0.handsal }), ("orgs", { $0.orgs })]
        for (name, path) in levels {
            for mode in [mode_t(0o775), 0o757, 0o777] {
                let rig = try PinRig()
                chmod(path(rig), mode)
                let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
                #expect(report == PinReport(reason: .pinOwner), "\(name) \(String(mode, radix: 8))")
                chmod(path(rig), 0o755)
                #expect(rig.entries().isEmpty)
            }
        }
        // a symlink in place of `orgs`, and a file in place of `handsal`
        let linked = try PinRig(withHandsalDirectory: true)
        try FileManager.default.removeItem(atPath: linked.orgs)
        try PinRig.directory(linked.tools + "/elsewhere", 0o755)
        symlink(linked.tools + "/elsewhere", linked.orgs)
        #expect(try linked.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"])).reason == .pinOwner)
        #expect(try FileManager.default.contentsOfDirectory(atPath: linked.tools + "/elsewhere").isEmpty)
        let flat = try PinRig(withHandsalDirectory: false)
        try Data().write(to: URL(fileURLWithPath: flat.handsal))
        #expect(try flat.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"])).reason == .pinOwner)
    }

    @Test("an existing directory is never repaired")
    func aRefusedDirectoryIsLeftAlone() throws {
        let rig = try PinRig()
        chmod(rig.orgs, 0o775)
        _ = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(rig.attributes(rig.orgs).st_mode & 0o7777 == 0o775)
        chmod(rig.orgs, 0o755)
    }

    @Test("the system's own Library and Application Support are not the helper's to create: absent, it is internal")
    func theSystemDirectoriesAreNotCreated() throws {
        let rig = try PinRig(withHandsalDirectory: false)
        try FileManager.default.removeItem(atPath: rig.root + "/Library/Application Support")
        let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report == PinReport(reason: .internal) && report.exit == 5)
        #expect(!FileManager.default.fileExists(atPath: rig.root + "/Library/Application Support"))
    }

    @Test("directories created at step 0 stay when a later step fails")
    func createdDirectoriesStay() throws {
        let rig = try PinRig(withHandsalDirectory: false)
        let report = try rig.helper(answering: PinRig.invalidAnswer("fork")).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report.reason == .pinInvalid)
        #expect(FileManager.default.fileExists(atPath: rig.orgs) && rig.entries().isEmpty)
    }

    /// As root `fchown` is never refused, so the fault cannot be injected; the platform run (T5.20) leaves this one out.
    @Test("a failure after the temporary file exists removes the helper's own temporary file and writes nothing",
          .disabled(if: getuid() == 0, "fchown to a foreign group cannot fail as root"))
    func aFailedWriteLeavesNoTemporaryFile() throws {
        // the group the helper would give the file is one this user is not in, so `fchown` is refused
        // after the exclusive create and before the rename; directories and lock were made right already
        let rig = try PinRig(owner: Owner(uid: getuid(), gid: 1))
        let lock = rig.handsal + "/pin.lock"
        FileManager.default.createFile(atPath: lock, contents: nil)
        chmod(lock, 0o644)
        let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report == PinReport(reason: .internal, inner: "ok") && report.exit == 5)
        #expect(rig.entries().isEmpty, "\(rig.entries())")
    }

    // MARK: Lock

    @Test("sgn/pin-helper-lock-held-refused: a lock held by another run is internal, nothing is written")
    func aHeldLockIsRefused() throws {
        let rig = try PinRig(withHandsalDirectory: false)
        // a first run creates the lock file; then another process holds it
        _ = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        try FileManager.default.removeItem(atPath: rig.pinPath(org: org))
        let fd = open(rig.handsal + "/pin.lock", O_RDWR | O_CLOEXEC)
        #expect(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0)
        defer { flock(fd, LOCK_UN); close(fd) }
        let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
        #expect(report == PinReport(reason: .internal) && report.exit == 5)
        #expect(text(report) == #"{"inner_reason":null,"reason":"internal","written":"no"}"#)
        #expect(rig.entries().isEmpty)
        // the checker did not run: the lock comes before step 1
        flock(fd, LOCK_UN)
        #expect(try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"])).reason == .ok)
    }

    @Test("the lock is released when the run ends, so the next run takes it")
    func theLockIsReleased() throws {
        let rig = try PinRig()
        let helper = try rig.helper(answering: valid(genesisA))
        for _ in 0..<3 { #expect(helper.run(arguments: [], stdin: PinRig.request(names: ["a"])).reason == .ok) }
        // and after a failure too
        let failing = try rig.helper(answering: PinRig.invalidAnswer("fork"))
        #expect(failing.run(arguments: [], stdin: PinRig.request(names: ["a"])).reason == .pinInvalid)
        #expect(helper.run(arguments: [], stdin: PinRig.request(names: ["a"])).reason == .ok)
    }

    @Test("a lock file that is not the helper's own is pin_owner: a symlink, a writable file, a second link")
    func aLockFileThatIsNotTheHelpersIsRefused() throws {
        for prepare in [{ (rig: PinRig) in symlink(rig.tools, rig.handsal + "/pin.lock"); return }, { (rig: PinRig) in
            let path = rig.handsal + "/pin.lock"
            FileManager.default.createFile(atPath: path, contents: nil)
            chmod(path, 0o666)
        }, { (rig: PinRig) in
            let path = rig.handsal + "/pin.lock"
            FileManager.default.createFile(atPath: path, contents: nil)
            chmod(path, 0o644)
            link(path, rig.tools + "/second-link")
        }] {
            let rig = try PinRig()
            prepare(rig)
            let report = try rig.helper(answering: valid(genesisA)).run(arguments: [], stdin: PinRig.request(names: ["a"]))
            #expect(report.reason == .pinOwner || report.reason == .internal)
            #expect(rig.entries().isEmpty)
        }
    }

    // MARK: The checker

    @Test("the checker is given exactly the bytes of the input object, under an empty environment")
    func theCheckerSeesTheInputAndNoEnvironment() throws {
        let rig = try PinRig()
        setenv("HANDSAL_TEST_LEAK", "yes", 1)
        defer { unsetenv("HANDSAL_TEST_LEAK") }
        let input = PinRig.request(names: ["a", "b"], acts: ["act-one", "act-two"])
        _ = try rig.helper(answering: valid(genesisB)).run(arguments: [], stdin: input)
        #expect(try Data(contentsOf: URL(fileURLWithPath: rig.seen)) == Data(input.dropLast()), "the object, without its framing LF")
        let environment = try String(contentsOfFile: rig.environmentSeen, encoding: .utf8)
        #expect(!environment.contains("HANDSAL_TEST_LEAK") && !environment.contains("PATH"), "\(environment)")
    }

    @Test("a checker that is missing, crashes, exits nonzero or answers something that is not one JCS line is internal")
    func aBrokenCheckerIsInternal() throws {
        let rig = try PinRig()
        let sound = PinRig.pin(org: org, genesis: genesisA)
        let escaped = PinRig.validAnswer(pin: sound)
        let answers: [String] = [
            "", "not json", "{}", #"[]"#, escaped + escaped,
            #"{"pin":null,"reason":"ok","valid":true}"#,                       // valid with no pin
            #"{"pin":"x","reason":"ok","valid":true}"#,                        // a pin that is no pin
            #"{"pin":null,"reason":"ok","valid":false}"#,                      // invalid with reason ok
            PinRig.validAnswer(pin: sound).replacingOccurrences(of: #""reason":"ok""#, with: #""reason":"fork""#), // valid with another reason
            #"{"pin":"\#(String(sound.dropLast()))","reason":"ok","valid":true}"#,
            #"{"reason":"ok","valid":false}"#, #"{"valid":false,"reason":"x_y","pin":null}"#,   // unsorted / missing
            #"{"pin":null,"reason":"Bad","valid":false}"#, #"{"pin":null,"reason":"","valid":false}"#,
            #"{"pin": null,"reason":"fork","valid":false}"#,
            #"{"pin":null,"reason":"fork","valid":"yes"}"#, #"{"pin":null,"reason":1,"valid":false}"#,
            String(repeating: "x", count: 5000),
        ]
        for answer in answers {
            let report = try rig.helper(answering: answer).run(arguments: [], stdin: PinRig.request(names: ["a"]))
            #expect(report == PinReport(reason: .internal) && report.exit == 5, "\(answer.prefix(60))")
        }
        #expect(try rig.helper(answering: valid(genesisA), exit: 3).run(arguments: [], stdin: PinRig.request(names: ["a"])) == PinReport(reason: .internal))
        let missing = rig.helper(CheckerCommand(executable: rig.tools + "/absent", arguments: ["genesis-check"]))
        #expect(missing.run(arguments: [], stdin: PinRig.request(names: ["a"])) == PinReport(reason: .internal))
        #expect(rig.entries().isEmpty)
    }

    @Test("the installed helper runs the production checker at its fixed path and nothing else")
    func theInstalledHelperHasFixedPaths() {
        let helper = PinHelper.installed()
        #expect(helper.checker == CheckerCommand(executable: "/Library/Application Support/handsal/bin/handsal-check", arguments: ["genesis-check"]))
        #expect(helper.directories.root == "/" && helper.owner == .administrator)
        #expect(helper.directories.orgs == "/Library/Application Support/handsal/orgs" && helper.directories.lock == "/Library/Application Support/handsal/pin.lock")
    }

    // MARK: Report

    @Test("the exit code follows the reason, and a report line is one JCS line")
    func exitCodesFollowTheReason() {
        let table: [(PinReason, Int32)] = [(.ok, 0), (.malformedInput, 2), (.unparseableInput, 2), (.pinInvalid, 3), (.pinOwner, 3),
                                           (.pinMalformed, 3), (.pinRollback, 3), (.internal, 5)]
        #expect(Set(table.map(\.0)) == Set(PinReason.allCases))
        for (reason, exit) in table {
            let report = PinReport(reason: reason, inner: reason == .ok ? "ok" : nil, written: reason == .ok)
            #expect(report.exit == exit && report.outcome.exit == exit)
            #expect(!text(report).contains("\n"))
        }
    }
}

/// The ceremony reads the helper's report through the helper's own parser, so the report format
/// has one owner (GP-21 Output: the ceremony accepts only a line whose R matches the exit code).
@Suite("pin helper report, as the ceremony reads it (GP-21)")
struct PinReportReadTests {
    private func read(_ line: String, exit: Int32) -> PinReport? { PinReport.read(output: Array(line.utf8), exit: exit) }

    @Test("every report the helper writes reads back to itself, with its own exit code")
    func theHelperReadsItsOwnReports() {
        let reports = [PinReport(reason: .ok, inner: "ok", written: true), PinReport(reason: .pinRollback, inner: "ok"),
                       PinReport(reason: .pinInvalid, inner: "genesis_unsigned"), PinReport(reason: .malformedInput),
                       PinReport(reason: .unparseableInput), PinReport(reason: .pinOwner), PinReport(reason: .pinMalformed),
                       PinReport(reason: .internal), PinReport(reason: .internal, inner: "ok")]
        for report in reports { #expect(PinReport.read(output: report.line + [0x0A], exit: report.exit) == report, "\(report)") }
    }

    @Test("a line whose reason does not match the exit code, or that is not exactly the report, reads as nil")
    func onlyAMatchingLineReads() {
        let ok = #"{"inner_reason":"ok","reason":"ok","written":"yes"}"#
        #expect(read(ok + "\n", exit: 0) != nil)
        for (line, exit) in [(ok + "\n", Int32(3)), (ok + "\n", 1), (ok + "\n", 5), (ok, 0), (ok + "\n\n", 0), ("", 0), (ok + ok + "\n", 0),
                             (#"{"inner_reason":"ok","reason":"ok","written":"no"}"# + "\n", 0),               // ok but not written
                             (#"{"inner_reason":"ok","reason":"pin_owner","written":"yes"}"# + "\n", 3),      // written without ok
                             (#"{"inner_reason":"ok","reason":"mystery","written":"no"}"# + "\n", 3),
                             (#"{"inner_reason":null,"reason":"ok","written":"yes"}"# + "\n", 0) as (String, Int32),   // ok with no inner reason
                             (#"{"reason":"ok","written":"yes"}"# + "\n", 0), (#"{"inner_reason":"ok","reason":"ok","written":"yes","x":"y"}"# + "\n", 0),
                             (#"{"inner_reason": "ok","reason":"ok","written":"yes"}"# + "\n", 0), (#"{"written":"yes","reason":"ok","inner_reason":"ok"}"# + "\n", 0),
                             (#"{"inner_reason":"ok","reason":"ok","written":true}"# + "\n", 0)] {
            #expect(read(line, exit: exit) == nil, "\(line) \(exit)")
        }
    }
}
