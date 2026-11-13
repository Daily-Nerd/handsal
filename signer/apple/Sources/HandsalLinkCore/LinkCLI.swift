import HandsalCore

/// `handsal-link` (SG-09): a separate executable outside the signer, because it needs no key and
/// no prompt, and because a signer command that makes a code would be a way for a caller to
/// choose it. It takes no argument and reads no stdin.
///
/// What it does: draws a QR code of a fresh one-time code on the display channel (the controlling
/// terminal, never stdout), says the `Link code` hash12 beside it for comparison with the draft,
/// and writes one JCS line `{"link_code_hash":hashstr}` on stdout, which is what `device.add` and
/// `member.add` bind. The code itself is never written to stdout.
/// Failure modes, each with nothing drawn and no hash on stdout: an argument is `unsupported_command`
/// (exit 2), no display channel is `no_display` (exit 4: a code nobody saw is of no use), a random
/// source that fails is `internal` (exit 5).
/// `link_code_hash` is a one-time uniqueness value; it proves nothing about the QR flow (SG-09).
public enum LinkCLI {
    public static func run(arguments: [String], random: () -> [UInt8] = LinkCode.systemRandom,
                           display: () throws -> any Display) -> Outcome {
        guard arguments.isEmpty else { return ExitCodes.outcome(for: Refusal("unsupported_command")) }
        do {
            let code = try LinkCode.make(random: random)
            guard let modules = QRCode.modules(for: code.text) else { throw Refusal("internal") }
            let channel = try display()
            try channel.show(QRCode.terminalLines(modules).joined(separator: "\n") + "\n")
            try channel.show("Link code \(Render.hash12(code.hash))\nScan the code on the new device. It is shown once.\n")
            return Outcome(exit: 0, line: try Emit.resultLine(.object(["link_code_hash": .string(code.hash)])))
        } catch let refusal as Refusal {
            return ExitCodes.outcome(for: refusal)
        } catch {
            return ExitCodes.outcome(for: Refusal("internal"))
        }
    }
}
