import HandsalConformance
import HandsalCore

// The conformance executable (CF-04): `render` and `emit` for the vector harness, nothing else.
// It holds no key, shows no prompt and reads neither a clock nor a random source. Never installed.
ProcessIO.finish(ConformanceCLI.run(arguments: ProcessIO.arguments, readStdin: ProcessIO.readStdinBounded))
