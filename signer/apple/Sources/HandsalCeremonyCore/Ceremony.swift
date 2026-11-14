import HandsalCore
import HandsalPinCore

/// The enrollment ceremony (SG-12, GP-12): a procedure, not a signer command, run by its own
/// executable `handsal-ceremony` over the same core as everything else. Which program a process is
/// is decided by the file that was started, never by a flag.
///
/// The steps, each before the next, and the pin write is the last write:
///   1  the bag arrives as input (`CeremonyInput`)
///   2  refuse a fixture profile and a fixture kid, a device's or the relay's     (`Refusals`)
///   3  `genesis-check` on `{acts, lineage}`; stop unless `valid:true`
///   4  refuse a policy without a spare person and a role holder's PIN-capable key  (`Refusals`)
///   5  show the render (RN-08 or RN-10, the witness lines included) and flag single-device persons
///   6  for a change, the line about H in the previous epoch                          (`Aids`)
///   7  for a change, the removed-key lines                                           (`Aids`)
///   8  show hash12 of the `genesis` in the exact pin line and ask for the comparison
///   9  hand `{acts, lineage}` to the pin helper through one `/usr/bin/sudo -k` run  (`SudoChannel`)
///  10  run `sync` on `{acts, lineage, org}`: the production checker writes the per-machine store (CF-09)
///  11  run `enrolled` on `{device_kid, org}`, which is the judge
/// Nothing in this file removes, truncates or restores a pin, and a failure after the write
/// reports and leaves it (GP-21): a pin the ceremony would undo is a pin an agent could provoke it
/// to undo. The pin helper, not the ceremony, owns directories, monotonicity and attributes.
/// The helper's report is accepted only if its reason matches its exit code (`PinReport.read`);
/// otherwise the write is `unknown` and the next `enrolled`, which reads the real pin, decides.
public struct Ceremony: Sendable {
    let checker: any CeremonyChecker
    let helper: any HelperChannel
    let console: any Console
    let context: GenesisContext

    public init(checker: any CeremonyChecker, helper: any HelperChannel, console: any Console, context: GenesisContext = GenesisContext()) {
        self.checker = checker; self.helper = helper; self.console = console; self.context = context
    }

    public func run(arguments: [String], stdin: [UInt8]) -> CeremonyResult {
        do {
            return try perform(CeremonyInput.read(arguments: arguments, stdin: stdin))
        } catch let stop as Stop {
            return stop.result
        } catch let refusal as Refusal where refusal.code == "no_display" {
            return Stop.noTerminal().result
        } catch {
            return Stop.refused("internal").result
        }
    }

    private func perform(_ input: CeremonyInput) throws -> CeremonyResult {
        let candidate = input.lineage[input.lineage.count - 1].doc
        try Refusals.beforeAnything(input.lineage)
        let pin = try accepted(input)
        try Refusals.policy(of: candidate, context: context)

        let previous = input.lineage.count > 1 ? input.lineage[input.lineage.count - 2].doc : nil
        let render: (firstLine: String, lines: [String])
        do { render = try Render.genesisText(document: candidate, previous: previous, context: context) } catch let refusal as Refusal {
            throw Stop.refused(refusal.code)
        }
        try console.requireForeground()
        try console.show(([render.firstLine] + render.lines).joined(separator: "\n") + "\n")
        for person in Self.singleDevicePersons(candidate) {
            try console.show("\(person) holds a single device: if it is lost or its biometrics change, recovery needs a device.add from other devices (SG-11)\n")
        }
        if previous != nil {
            try console.show(try Aids.gather(input: input, candidate: candidate, checker: checker).lines.joined(separator: "\n") + "\n")
        }

        let hash12 = Render.hash12(pin.genesis)
        try console.show("Pin line:\n\(pin.text.dropLast())\nhash12 of the genesis: \(hash12)\n")
        guard try console.confirm("Is \"\(hash12)\" the hash12 in line 1 of the genesis.sign prompt you saw on each signing device?") else {
            throw Stop.refused("not_confirmed")
        }

        try console.requireForeground()
        try submit(input)
        return try judge(input)
    }

    // MARK: step 3

    private struct Pin { let text: String; let genesis: String }

    /// The pin line of a lineage the checker accepts, checked against the hashes this side computes.
    private func accepted(_ input: CeremonyInput) throws -> Pin {
        let answer = try checker.run("genesis-check", input: input.lineageInput())
        if let error = answer["error"]?.str { throw Stop.refused(error) }
        guard case .bool(let valid)? = answer["valid"], let reason = answer["reason"]?.str else { throw Stop.refused("internal") }
        guard valid else { throw Stop.refused(reason) }
        guard let text = answer["pin"]?.str, case .success(let line) = Subset.parse(Array(text.utf8.dropLast()), maxSize: 512), text.hasSuffix("\n"),
              let genesis = line["genesis"]?.str, let org = line["org"]?.str, Forms.isHashstr(genesis), Forms.isHashstr(org) else {
            throw Stop.refused("internal")
        }
        // The pin is for this lineage: the org of its first document and the hash of its last.
        guard org == input.org, genesis == (try? Genesis.docHash(input.lineage[input.lineage.count - 1].doc)) else {
            throw Stop.refused("genesis_pin_mismatch")
        }
        return Pin(text: text, genesis: genesis)
    }

    // MARK: steps 5 and 9

    /// Persons of the document with exactly one device, in member order (SG-11).
    static func singleDevicePersons(_ candidate: JValue) -> [String] {
        var count: [String: Int] = [:]
        for device in candidate["devices"]?.list ?? [] { if let person = device["person"]?.str { count[person, default: 0] += 1 } }
        return (candidate["members"]?.list ?? []).compactMap { $0["id"]?.str }.filter { count[$0] == 1 }
    }

    /// One run of the helper, and its report: only a report that matches its exit code counts.
    private func submit(_ input: CeremonyInput) throws {
        var line = try input.lineageInput()
        line.append(0x0A)
        let reply = try helper.submit(line)
        guard let report = PinReport.read(output: reply.output, exit: reply.exit) else { throw Stop.untrustedReport() }
        guard report.reason == .ok else { throw Stop.failedWrite(report.reason.rawValue) }
    }

    // MARK: steps 10 and 11

    /// `sync` gives the checker the view it will read (CF-09), and only `ok` counts: a refusal writes
    /// nothing, and a `fork` is written but is not an enrolled machine. From here the pin is written, so
    /// every failure is `afterWrite`.
    private func synced(_ input: CeremonyInput) throws {
        let answer: JValue
        do { answer = try checker.run("sync", input: input.syncInput()) } catch { throw Stop.afterWrite("internal") }
        if let error = answer["error"]?.str { throw Stop.afterWrite(error) }
        guard case .object(let members) = answer, Set(members.keys) == ["reason", "synced_at"], let reason = members["reason"]?.str,
              let written = members["synced_at"], written == .null || written.str != nil,
              (written != .null) == (reason == "ok" || reason == "fork") else { throw Stop.afterWrite("internal") }
        guard reason == "ok" else { throw Stop.afterWrite(reason) }
    }

    /// `enrolled` is the judge. From here the pin is written, so every failure is `afterWrite`.
    private func judge(_ input: CeremonyInput) throws -> CeremonyResult {
        try synced(input)
        let answer: JValue
        do { answer = try checker.run("enrolled", input: input.enrolledInput()) } catch { throw Stop.afterWrite("internal") }
        if let error = answer["error"]?.str { throw Stop.afterWrite(error) }
        guard case .object(let members) = answer, Set(members.keys) == ["enrolled", "reason"], case .bool(let enrolled)? = members["enrolled"],
              let reason = members["reason"]?.str, enrolled == (reason == "ok") else { throw Stop.afterWrite("internal") }
        guard enrolled else { throw Stop.afterWrite(reason) }
        // The pin is written and `enrolled` has judged: this line is an aid, so a console that fails now
        // must not turn a machine that is enrolled into a failed ceremony.
        _ = try? console.show("Enrolled: this machine holds the pin of \(Render.hash12(input.org)) and its evidence folds.\n")
        return CeremonyResult(reason: "ok", written: "yes", exit: 0)
    }
}
