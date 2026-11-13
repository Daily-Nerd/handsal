import Foundation
import HandsalCore
import Testing
@testable import HandsalCeremonyCore

private func script(_ body: String) throws -> (path: String, cleanup: () -> Void) {
    let directory = NSTemporaryDirectory() + "ceremony-parts-\(UUID().uuidString)"
    try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    let path = directory + "/tool"
    try ("#!/bin/sh\n" + body + "\n").write(toFile: path, atomically: true, encoding: .utf8)
    chmod(path, 0o755)
    return (path, { try? FileManager.default.removeItem(atPath: directory) })
}

@Suite("the ceremony's parts (SG-14, CF-03)")
struct CeremonyPartsTests {
    @Test("the production checker is run by absolute path with the command as its only argument and nothing of the caller's environment")
    func theCheckerIsRunPlainly() throws {
        let tool = try script(#"""
        cat > /dev/null; printf '{"args":"%s","leak":"%s"}\n' "$*" "$(/usr/bin/env | /usr/bin/grep -c HANDSAL_CEREMONY_LEAK)"
        """#)
        defer { tool.cleanup() }
        setenv("HANDSAL_CEREMONY_LEAK", "yes", 1)
        defer { unsetenv("HANDSAL_CEREMONY_LEAK") }
        let answer = try ProductionChecker(executable: tool.path).run("enrolled", input: Array("{}".utf8))
        #expect(answer["args"] == str("enrolled") && answer["leak"] == str("0"), "\(answer)")
        #expect(ProductionChecker.installed.executable == "/Library/Application Support/handsal/bin/handsal-check")
    }

    @Test("a checker that crashes, answers two lines, no line, or something that is not I-JSON is internal")
    func aBrokenCheckerIsInternal() throws {
        for body in ["exit 3", "printf '{}\\n{}\\n'", "printf ''", "printf 'not json\\n'", "printf '{}'", "printf '{\"a\":1,\"a\":2}\\n'",
                     "cat > /dev/null; printf '{}\\n'; exit 1", "kill -9 $$"] {
            let tool = try script(body)
            defer { tool.cleanup() }
            #expect(throws: Refusal("internal")) { try ProductionChecker(executable: tool.path).run("fold", input: []) }
        }
        #expect(throws: Refusal("internal")) { try ProductionChecker(executable: "/nonexistent/handsal-check").run("fold", input: []) }
    }

    @Test("a checker that answers before it reads its input does not stop the ceremony")
    func anEarlyAnswerIsFine() throws {
        let tool = try script(#"printf '{"ok":"yes"}\n'"#)
        defer { tool.cleanup() }
        let big = [UInt8](repeating: 0x20, count: 4_000_000)
        #expect(try ProductionChecker(executable: tool.path).run("fold", input: big)["ok"] == str("yes"))
    }

    @Test("the sudo channel returns the helper's exit code and what it wrote, from one run")
    func theChannelReturnsTheReply() throws {
        let log = NSTemporaryDirectory() + "sudo-log-\(UUID().uuidString)"
        let fake = try script("cat > \(log).in; printf '%s\\n' \"$*\" >> \(log); printf '{\"reply\":true}\\n'; exit 3")
        defer { fake.cleanup(); try? FileManager.default.removeItem(atPath: log); try? FileManager.default.removeItem(atPath: log + ".in") }
        let channel = SudoChannel(sudo: fake.path, helper: "/Library/Application Support/handsal/bin/handsal-pin")
        let reply = try channel.submit(Array("one line\n".utf8))
        #expect(reply == HelperReply(exit: 3, output: Array("{\"reply\":true}\n".utf8)))
        #expect(try String(contentsOfFile: log, encoding: .utf8) == "-k /Library/Application Support/handsal/bin/handsal-pin\n", "one run")
        #expect(try String(contentsOfFile: log + ".in", encoding: .utf8) == "one line\n")
    }

    @Test("the sudo channel starts sudo in the ceremony's own process group, so sudo can own the terminal and turn echo off")
    func sudoSharesTheCeremonysProcessGroup() throws {
        // A child in a new process group is a background group on the terminal: it cannot clear ECHO
        // and its reads of /dev/tty fail with EIO, so a password would be typed in the clear.
        let fake = try script("cat > /dev/null; ps -o pgid= -p $$ | tr -d ' '; exit 0")
        defer { fake.cleanup() }
        let reply = try SudoChannel(sudo: fake.path, helper: "x").submit(Array("line\n".utf8))
        #expect(String(decoding: reply.output, as: UTF8.self) == "\(getpgrp())\n")
    }

    @Test("the checker too is started in the ceremony's process group: one way to start a child")
    func theCheckerSharesTheProcessGroup() throws {
        let tool = try script(#"cat > /dev/null; printf '{"pgid":"%s"}\n' "$(ps -o pgid= -p $$ | tr -d ' ')""#)
        defer { tool.cleanup() }
        #expect(try ProductionChecker(executable: tool.path).run("fold", input: [])["pgid"] == str("\(getpgrp())"))
    }

    @Test("a sudo that cannot be started is internal, and a missing terminal is no_display")
    func failuresAreNamed() throws {
        #expect(throws: Refusal("internal")) { try SudoChannel(sudo: "/nonexistent/sudo", helper: "x").submit([]) }
        let console = TTYConsole(path: "/nonexistent/tty")
        #expect(throws: Refusal("no_display")) { try console.show("x") }
        #expect(throws: Refusal("no_display")) { try console.confirm("x?") }
    }

    @Test("a terminal that is not this process's own controlling terminal is not a foreground terminal")
    func aForeignPtyIsNotForeground() throws {
        var master: Int32 = 0, slave: Int32 = 0
        var name = [CChar](repeating: 0, count: 128)
        #expect(openpty(&master, &slave, &name, nil, nil) == 0)
        defer { close(master); close(slave) }
        #expect(throws: Refusal("no_display")) { try TTYConsole(path: String(cString: name)).requireForeground() }
        #expect(throws: Refusal("no_display")) { try TTYConsole(path: "/nonexistent/tty").requireForeground() }
    }

    @Test("only y or yes, in any case, is a yes")
    func onlyYesIsYes() {
        for yes in ["y", "Y", "yes", "YES", "Yes"] { #expect(TTYConsole.isYes(yes)) }
        for no in ["", "n", "no", "yy", " y", "y ", "ye", "yes!", "sure", "1"] { #expect(!TTYConsole.isYes(no), "\(no)") }
    }

    @Test("the checker's pin is for this lineage: a pin for another genesis or another org is refused")
    func aPinForAnotherLineageIsRefused() {
        var docs = Docs()
        let original = docs.document()
        let lineage = [(doc: original, sigs: [String]())]
        for pin in [pinLine(genesis: hash("another"), org: docHash(original)), pinLine(genesis: docHash(original), org: hash("another org"))] {
            let checker = FakeChecker(["genesis-check": [checkAnswer(pin: pin)]])
            let helper = FakeHelper(), console = FakeConsole()
            let result = Ceremony(checker: checker, helper: helper, console: console).run(arguments: [], stdin: ceremonyInput(lineage: lineage))
            #expect(result == CeremonyResult(reason: "genesis_pin_mismatch", written: "no", exit: 1))
            #expect(helper.lines.isEmpty && console.questions.isEmpty)
        }
    }

    @Test("a missing terminal ends the ceremony with no_display, exit 4, before anything is written")
    func noTerminalIsExitFour() {
        var docs = Docs()
        let original = docs.document()
        let lineage = [(doc: original, sigs: [String]())]
        let checker = FakeChecker(["genesis-check": [checkAnswer(pin: pinLine(genesis: docHash(original), org: docHash(original)))]])
        let helper = FakeHelper()
        let result = Ceremony(checker: checker, helper: helper, console: FakeConsole(answers: [])).run(arguments: [], stdin: ceremonyInput(lineage: lineage))
        #expect(result == CeremonyResult(reason: "no_display", written: "no", exit: 4))
        #expect(helper.lines.isEmpty)
    }
}
