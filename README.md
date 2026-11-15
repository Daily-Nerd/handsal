# handsal

handsal signs human approvals with a hardware-bound P-256 key. Every signature needs a fresh biometric check (Touch ID, Face ID, or Windows Hello), so software alone cannot produce one.

## Why

Plenty of systems record that a person approved something, usually as a string like `human` in a file. Anything with file access can write that string. Signing with a GPG key or a GitHub token does not fix it either, because automated agents run with those keys too. Those signatures show which key was used, not that someone was actually there.

handsal closes that gap. The key lives in hardware (the Secure Enclave on a Mac, the TPM behind Windows Hello on Windows) and each use requires a biometric check. No program on the machine, including the one asking for the approval, can sign on its own.

## The name

A handsal is an Old Norse handshake that sealed a deal in front of witnesses. The witnesses here are other people and programs that check the result later. [vitni](https://github.com/Daily-Nerd/vitni) verifies, handsal signs.

## What this repo holds

- A profile spec on top of vitni's act format: which fields are signed, which methods exist, how the set of trusted keys is derived from a signed log.
- Conformance vectors, so every implementation can be tested against the same cases, including every rejection reason.
- A reference checker that runs those vectors.
- A macOS signer CLI written in Swift, with the installer for the administrator paths.
- A Windows signer exe, planned for a later tag. On Windows under WSL2, the checker will use the native Windows exe.

The spec comes first, in [spec/profile.md](spec/profile.md), [spec/profile-interfaces.md](spec/profile-interfaces.md) and [spec/profile-part3.md](spec/profile-part3.md), three files of one text. The signers are built against the vectors, not the other way around.

## Guarantees

- Only a hardware-bound P-256 key from a class the spec lists counts as proof that a human was present. A machine without one is treated as unproven, never as approved.
- The private key never leaves the chip.
- One fresh biometric check per signature. A caller cannot hand in an authentication context to skip it.
- The text shown in the approval prompt is built by handsal from the payload. The caller does not supply it.
- Fail closed. A missing key, a denied touch, or a stale key registry means refusal, never a silent skip.
- Repositories hold key ids only, never key material.

## What the approval screen does not give you

The approval screen is not a trust boundary. Any single touch may end up signing bytes an attacker chose, and what the screen shows is not proof of what was signed. So one approval from one person is never treated as enough. Trust comes from a quorum of distinct people, each approving with their own key. Every change to who holds keys needs at least two of them, and the group must keep one spare person beyond that, so an organization starts with at least three.

## Status

The spec is complete for the first tag, and the conformance vectors and the reference checker run against it. The first tag is for macOS only. The Windows signer, its installer and the Windows Hello key class come in a later tag.

Windows is unverified. The Windows key class depends on a hardware check that has not passed yet: whether an app can require fingerprint or face and refuse the PIN. Until it does, the registry of the first tag holds no Windows class, and Windows support is planned, not working. The check is a script in [spikes/windows-hello](spikes/windows-hello).

Installing the macOS binaries is a person-run procedure that compares each file with the SHA-256 values published for the tag, read on a second device. The script and its usage are in [tools/install](tools/install).

## Requirements

- macOS: a Mac with a Secure Enclave and Touch ID. Apple silicon, or an Intel Mac with a T2 chip.
- Windows (later tag): Windows 11 with a TPM 2.0 and Windows Hello set up. WSL2 is supported through the native Windows exe. Subject to the hardware check above.

## License

Apache-2.0. See [LICENSE](LICENSE).
