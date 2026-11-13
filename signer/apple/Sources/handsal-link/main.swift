import HandsalCore
import HandsalLinkCore

// Plumbing only: no argument, no stdin, one line on stdout, the exit code out. The display is the
// controlling terminal, as for the signer.
ProcessIO.finish(LinkCLI.run(arguments: ProcessIO.arguments, display: { try TTYDisplay.open(path: TTYDisplay.standardPath) }))
