import Darwin
import HandsalCeremonyCore
import HandsalCore

// Plumbing only: the arguments and stdin in, one result line on stdout, the exit code out. The
// person is at the controlling terminal: what the ceremony shows goes there, never to stdout, and
// the one question is answered there too. Every decision is in `Ceremony.run`.
let console = TTYConsole()
let ceremony = Ceremony(checker: ProductionChecker.installed, helper: SudoChannel.installed, console: console)
ProcessIO.finish(ceremony.run(arguments: ProcessIO.arguments, stdin: ProcessIO.readStdinBounded()).outcome)
