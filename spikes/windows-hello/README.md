# Windows Hello spike

This is a short test that answers two questions. The first: can Windows give handsal the kind of signing key it needs? The second (step S11, near the end): can Windows also give handsal a second, separate key that needs no fingerprint, so that reading a message sent to this PC does not ask you to touch anything?

handsal signs human approvals with a key that lives in hardware and needs you to approve each signature. On a Mac that is the Secure Enclave. On Windows it would be Windows Hello, backed by the TPM chip. This script checks, on your PC, whether that works, and one question above all: can an app insist on fingerprint or face and refuse the PIN?

You do not need to know how to code. It takes about 15 minutes.

## What it does

- Reads basic facts about your PC: Windows version, whether it has a TPM, whether a fingerprint reader or face camera is set up.
- Creates a few test keys, uses them to sign dummy data, and **deletes them again at the end**.
- Near the end (S11), creates a test key that Windows Hello is not asked to guard, and checks that it can agree on a shared secret with a second key, with no window and no touch. This is the "read my mail" key. The signing key above is the "approve things as me" key, and it keeps needing your fingerprint or face. Nothing real is read or sent: both keys are throwaway test keys.
- Shows Windows Hello prompts and asks you short questions about what you saw.
- Writes one file, `handsal-spike-report.json`, in the folder where you run it.

It does not touch your real Windows sign-in, your files, or your Windows Hello setup. It does not connect to the internet. The report holds no name, computer name, or PIN.

## What you need

- Windows 10 or 11 with Windows Hello set up (fingerprint or face, plus a PIN).
- Windows PowerShell, which every Windows PC already has. Nothing to install.
- Optional: run PowerShell as Administrator to include the folder-permission test (S9). If you skip this, that one test is marked skipped and that is fine.

## How to run it

1. Put `spike.ps1` in a folder, for example `C:\handsal-spike`.
2. Open PowerShell in that folder (in File Explorer, type `powershell` in the address bar and press Enter).
3. Run:

   ```
   powershell -ExecutionPolicy Bypass -File .\spike.ps1
   ```

4. Follow the on-screen text. Press Enter to move on.

## What prompts to expect

Windows Hello windows will pop up several times. They sometimes open behind other windows, so look at the taskbar if nothing seems to happen. Most of the time, approve with your **fingerprint or face**.

There are three places where you do something different, and a fourth (S11) where you only answer one question:

1. **Cancel test (S7).** The script says so first. When the prompt appears, click Cancel or press Esc.
2. **PIN test (S10).** This is the important one. The script says "TRY TO USE YOUR PIN" before each prompt. When the prompt appears:
   - If you only see a fingerprint or face screen, look for **More choices**, **Sign-in options**, or a small PIN icon, and choose the PIN.
   - Type your PIN and approve.
   - If there is truly no way to reach the PIN, do not guess. Answer `x` when asked.
   - Then answer the question about what approved it. Be honest about what happened, even if it looks like a failure. Every answer is useful.
3. **PIN typing test (S10b).** Optional, and you can skip it by answering `s`. The script asks for your PIN once, hidden on screen. It keeps the PIN in memory only, types it into the Windows prompt as fake keystrokes to see whether a program can do that without you, and then wipes it. The PIN is never saved or sent anywhere. While the countdown runs, switch the prompt to its PIN box and then take your hands off the keyboard and mouse. If you would rather not enter your PIN at all, answer `s`.
4. **Key agreement test (S11).** Nothing to do here, and no prompt is expected. The script tries it three ways: with the PC's TPM chip, with the Windows Hello key provider, and with plain software as a comparison. If Windows does ask you for a fingerprint, face or PIN during this step, approve it and then answer `y` to the question at the end ("did any window appear"). That answer matters: it tells us the key was not really free of Windows Hello. If nothing appeared, answer `n`.

At the end, you will see a summary table on screen.

## Afterwards

The script deletes every test key it made. The summary says "Keys and folders removed: yes" when that worked. If it says "no", send the file anyway and say so.

**Please send back `handsal-spike-report.json`** to the person who gave you this script. You can open it in Notepad first if you want to see what is in it.

## Switches (optional)

- `-SkipInjection` skips the PIN typing test.
- `-SkipWsl` skips the check of Windows Subsystem for Linux.
- `-IncludeEnrollmentChange` adds a test where you add a fingerprint partway through.
