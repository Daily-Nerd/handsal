import HandsalPinCore

/// Proof that the pin helper reported a completed write. Only `PinWrite.submit` creates one (the initializer is
/// file-private), and the per-machine queries of the ceremony can be obtained only from one.
struct PinWritten: Sendable {
    fileprivate init() {}
}

/// Step 9: one run of the helper, and its report. Only a report that matches its exit code counts.
struct PinWrite: Sendable {
    let helper: any HelperChannel

    func submit(_ input: CeremonyInput) throws -> PinWritten {
        var line = try input.lineageInput()
        line.append(0x0A)
        let reply = try helper.submit(line)
        guard let report = PinReport.read(output: reply.output, exit: reply.exit) else { throw Stop.untrustedReport() }
        guard report.reason == .ok else { throw Stop.failedWrite(report.reason.rawValue) }
        return PinWritten()
    }
}
