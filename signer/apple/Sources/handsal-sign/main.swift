import HandsalCore
import HandsalSecureEnclave

// Plumbing only: arguments and stdin in, one line on stdout, the exit code out. Every decision is
// in `CLI.run`, which tests call without a process. The key is the Secure Enclave's.
let backend = SecureEnclaveBackend.standard()
let environment = Environment.live(backend: backend, lockPath: backend.lockPath)
ProcessIO.finish(CLI.run(arguments: ProcessIO.arguments, readStdin: ProcessIO.readStdinBounded, environment: environment))
