import HandsalCore
import HandsalPinCore

// Plumbing only: the argument list and stdin in, one report line on stdout, the exit code out.
// Every decision is in `PinHelper.run`. The installed helper has no test constructor: it is
// `PinHelper.installed()`, with the SG-14 checker path, the real root and root:wheel.
ProcessIO.finish(PinHelper.installed().run(arguments: ProcessIO.arguments, stdin: ProcessIO.readStdinBounded()).outcome)
