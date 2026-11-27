<#
handsal Windows Hello spike.

Answers, on one Windows machine, whether Windows can give the handsal signer
what the profile spec needs: a P-256 key held in hardware that cannot be
exported, one user prompt per signature, a raw 64-byte signature that verifies,
and (the hard one) a way for an app to demand biometrics and refuse the PIN.
Step S11 asks a second, separate question: can a TPM key that is NOT gated by
Windows Hello still do an ECDH key agreement, so that reading a message sealed
to this device needs no touch while signing still does.

No installs. No network calls. Nothing leaves this machine. The only output is
handsal-spike-report.json in the current directory.

Run:
  1. Check the script is the one you were given. The script prints its own SHA-256
     when it starts. You can also compute it first:
       Get-FileHash .\spike.ps1 -Algorithm SHA256
     Compare it with the hash published for this version by the person who gave
     you the script. The same hash is written into the report (script_sha256), so a
     report from an unknown copy of the script can be told apart.
  2. powershell -ExecutionPolicy Bypass -File .\spike.ps1
Works from Windows PowerShell 5.1 and PowerShell 7. PowerShell 7 hands over to
Windows PowerShell 5.1 (always present) because the WinRT calls need it.
#>
[CmdletBinding()]
param(
    [switch]$SkipInjection,
    [switch]$SkipWsl,
    [switch]$IncludeEnrollmentChange,
    [string]$ChildSign,
    [string]$ChildProvider
)

$ErrorActionPreference = 'Stop'
$script:SpikeVersion = '3'

if ($env:OS -ne 'Windows_NT') {
    Write-Host 'This spike only runs on Windows.'
    exit 2
}

# PowerShell 7 has no built-in WinRT projection. Hand over to 5.1.
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $fwd = @()
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $fwd += "-$k" } }
        else { $fwd += "-$k"; $fwd += [string]$v }
    }
    Write-Host 'PowerShell 7 detected. Continuing in Windows PowerShell 5.1.'
    & $ps51 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @fwd
    exit $LASTEXITCODE
}

# The SHA-256 of this very file. It goes into the report, so a report says which script made it.
$script:ScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLower()

# ---------------------------------------------------------------------------
# Native helpers (inline C#, classic syntax so Windows PowerShell 5.1 compiles it)
# ---------------------------------------------------------------------------
$script:CSharp = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class HsKey
{
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, EntryPoint = "NCryptSetProperty")]
    static extern int NCryptSetPropertyPtr(IntPtr hObject, string pszProperty, IntPtr pbInput, int cbInput, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll")]
    static extern int NCryptFinalizeKey(IntPtr hKey, uint dwFlags);
    [DllImport("ncrypt.dll")]
    static extern int NCryptSignHash(IntPtr hKey, IntPtr pPaddingInfo, byte[] pbHashValue, int cbHashValue, byte[] pbSignature, int cbSignature, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptExportKey(IntPtr hKey, IntPtr hExportKey, string pszBlobType, IntPtr pParameterList, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll")]
    static extern int NCryptDeleteKey(IntPtr hKey, uint dwFlags);
    [DllImport("ncrypt.dll")]
    static extern int NCryptFreeObject(IntPtr hObject);
    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    public string Provider;
    public string Name;
    public IntPtr HProv = IntPtr.Zero;
    public IntPtr HKey = IntPtr.Zero;
    public bool Finalized;
    public List<string> Log = new List<string>();
    public List<string> Applied = new List<string>();
    public List<string> Rejected = new List<string>();
    public int LastHr;
    public byte[] LastSig;

    public static string Hex(int hr) { return "0x" + ((uint)hr).ToString("X8"); }

    int Step(string what, int hr) { Log.Add(what + "=" + Hex(hr)); LastHr = hr; return hr; }

    public int OpenProvider(string provider)
    {
        Provider = provider;
        int hr = NCryptOpenStorageProvider(out HProv, provider, 0);
        return Step("openProvider", hr);
    }

    // uiFlags: -1 = do not set a UI policy. gesture: -1 = do not set, else 0 or 1.
    public int Create(string provider, string name, int uiFlags, int gesture, bool hwnd, bool overwrite)
    {
        Name = name;
        int hr = OpenProvider(provider);
        if (hr != 0) return hr;
        hr = Step("createPersistedKey", NCryptCreatePersistedKey(HProv, out HKey, "ECDSA_P256", name, 0, overwrite ? 0x80u : 0u));
        if (hr != 0) return hr;
        if (hwnd) SetHwnd();
        if (uiFlags >= 0) SetUiPolicy((uint)uiFlags);
        if (gesture >= 0) SetDword("PinCacheRequireGesture", (uint)gesture);
        hr = Step("finalize", NCryptFinalizeKey(HKey, 0));
        if (hr != 0) return hr;
        Finalized = true;
        return 0;
    }

    public int Open(string provider, string name)
    {
        Name = name;
        int hr = OpenProvider(provider);
        if (hr != 0) return hr;
        hr = Step("openKey", NCryptOpenKey(HProv, out HKey, name, 0, 0));
        if (hr == 0) Finalized = true;
        return hr;
    }

    public void SetHwnd()
    {
        IntPtr h = GetForegroundWindow();
        if (h == IntPtr.Zero) h = GetConsoleWindow();
        byte[] b = (IntPtr.Size == 8) ? BitConverter.GetBytes(h.ToInt64()) : BitConverter.GetBytes(h.ToInt32());
        int hr = NCryptSetProperty(HKey, "HWND Handle", b, b.Length, 0);
        Track("HWND Handle", hr);
    }

    public int SetDword(string prop, uint value)
    {
        byte[] b = BitConverter.GetBytes(value);
        int hr = NCryptSetProperty(HKey, prop, b, b.Length, 0);
        Track(prop + "=" + value, hr);
        return hr;
    }

    void Track(string label, int hr)
    {
        Log.Add("set[" + label + "]=" + Hex(hr));
        if (hr == 0) Applied.Add(label); else Rejected.Add(label + ":" + Hex(hr));
    }

    // NCRYPT_UI_POLICY { DWORD dwVersion; DWORD dwFlags; LPCWSTR pszCreationTitle; LPCWSTR pszFriendlyName; LPCWSTR pszDescription; }
    public int SetUiPolicy(uint flags)
    {
        int ps = IntPtr.Size;
        IntPtr mem = Marshal.AllocHGlobal(8 + 3 * ps);
        IntPtr s1 = Marshal.StringToHGlobalUni("handsal spike");
        IntPtr s2 = Marshal.StringToHGlobalUni("handsal spike test key");
        IntPtr s3 = Marshal.StringToHGlobalUni("Test key for the handsal Windows Hello spike");
        int hr;
        try
        {
            Marshal.WriteInt32(mem, 0, 1);
            Marshal.WriteInt32(mem, 4, (int)flags);
            Marshal.WriteIntPtr(mem, 8, s1);
            Marshal.WriteIntPtr(mem, 8 + ps, s2);
            Marshal.WriteIntPtr(mem, 8 + 2 * ps, s3);
            hr = NCryptSetPropertyPtr(HKey, "UI Policy", mem, 8 + 3 * ps, 0);
        }
        finally
        {
            Marshal.FreeHGlobal(s1); Marshal.FreeHGlobal(s2); Marshal.FreeHGlobal(s3); Marshal.FreeHGlobal(mem);
        }
        Track("UI Policy flags=" + flags, hr);
        return hr;
    }

    public byte[] GetBytes(string prop)
    {
        int cb;
        int hr = NCryptGetProperty(HKey, prop, null, 0, out cb, 0);
        LastHr = hr;
        if (hr != 0) return null;
        byte[] b = new byte[cb];
        hr = NCryptGetProperty(HKey, prop, b, cb, out cb, 0);
        LastHr = hr;
        if (hr != 0) return null;
        return b;
    }

    // Returns -1 when the property cannot be read.
    public long GetDword(string prop)
    {
        byte[] b = GetBytes(prop);
        if (b == null || b.Length < 4) return -1;
        return BitConverter.ToUInt32(b, 0);
    }

    public string GetStr(string prop)
    {
        byte[] b = GetBytes(prop);
        if (b == null) return null;
        return Encoding.Unicode.GetString(b).TrimEnd('\0');
    }

    public string Probe(string prop)
    {
        int cb;
        int hr = NCryptGetProperty(HKey, prop, null, 0, out cb, 0);
        return Hex(hr) + " size=" + cb;
    }

    public int Sign(byte[] digest, uint flags)
    {
        byte[] buf = new byte[512];
        int cb;
        LastSig = null;
        int hr = NCryptSignHash(HKey, IntPtr.Zero, digest, digest.Length, buf, buf.Length, out cb, flags);
        LastHr = hr;
        if (hr == 0) { LastSig = new byte[cb]; Array.Copy(buf, LastSig, cb); }
        return hr;
    }

    public byte[] ExportPublic()
    {
        int cb;
        int hr = NCryptExportKey(HKey, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, null, 0, out cb, 0);
        LastHr = hr;
        if (hr != 0) return null;
        byte[] b = new byte[cb];
        hr = NCryptExportKey(HKey, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, b, cb, out cb, 0);
        LastHr = hr;
        if (hr != 0) return null;
        return b;
    }

    // Tries to export private key material. Returns the HRESULT; 0 would mean the key is exportable.
    public int TryExportPrivate(string blobType)
    {
        int cb;
        int hr = NCryptExportKey(HKey, IntPtr.Zero, blobType, IntPtr.Zero, null, 0, out cb, 0);
        if (hr != 0) return hr;
        byte[] b = new byte[cb];
        hr = NCryptExportKey(HKey, IntPtr.Zero, blobType, IntPtr.Zero, b, cb, out cb, 0);
        Array.Clear(b, 0, b.Length);
        return hr;
    }

    public int Delete()
    {
        int hr = NCryptDeleteKey(HKey, 0);
        if (hr == 0) { HKey = IntPtr.Zero; }
        else { Close(); }
        Close();
        return hr;
    }

    public void Close()
    {
        if (HKey != IntPtr.Zero) { NCryptFreeObject(HKey); HKey = IntPtr.Zero; }
        if (HProv != IntPtr.Zero) { NCryptFreeObject(HProv); HProv = IntPtr.Zero; }
    }
}

public static class HsUtil
{
    static readonly byte[] N = new byte[] {
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51 };

    static byte[] HalfN()
    {
        byte[] h = new byte[32];
        int carry = 0;
        for (int i = 0; i < 32; i++) { int b = N[i]; h[i] = (byte)((b >> 1) | (carry << 7)); carry = b & 1; }
        return h;
    }

    // sig is raw R||S, 64 bytes.
    public static bool IsHighS(byte[] sig)
    {
        byte[] half = HalfN();
        for (int i = 0; i < 32; i++)
        {
            int a = sig[32 + i], b = half[i];
            if (a > b) return true;
            if (a < b) return false;
        }
        return false;
    }

    public static byte[] ToLowS(byte[] sig)
    {
        byte[] r = (byte[])sig.Clone();
        if (!IsHighS(sig)) return r;
        int borrow = 0;
        for (int i = 31; i >= 0; i--)
        {
            int d = N[i] - sig[32 + i] - borrow;
            if (d < 0) { d += 256; borrow = 1; } else { borrow = 0; }
            r[32 + i] = (byte)d;
        }
        return r;
    }

    // Converts a DER ECDSA signature to raw R||S (32 bytes each). Returns null if it is not DER.
    public static byte[] DerToRaw(byte[] der)
    {
        try
        {
            if (der.Length < 8 || der[0] != 0x30) return null;
            int p = 2;
            if ((der[1] & 0x80) != 0) p = 2 + (der[1] & 0x7F);
            if (der[p] != 0x02) return null;
            int rl = der[p + 1]; int rs = p + 2;
            int sp = rs + rl;
            if (der[sp] != 0x02) return null;
            int sl = der[sp + 1]; int ss = sp + 2;
            byte[] raw = new byte[64];
            CopyInt(der, rs, rl, raw, 0);
            CopyInt(der, ss, sl, raw, 32);
            return raw;
        }
        catch (Exception) { return null; }
    }

    static void CopyInt(byte[] src, int off, int len, byte[] dst, int dstOff)
    {
        while (len > 32 && src[off] == 0) { off++; len--; }
        Array.Copy(src, off, dst, dstOff + 32 - len, len);
    }

    // --- synthetic keyboard input (used only by the PIN injection test) ---
    [StructLayout(LayoutKind.Sequential)]
    struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)]
    struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Explicit)]
    struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)]
    struct INPUT { public uint type; public INPUTUNION u; }
    [DllImport("user32.dll", SetLastError = true)]
    static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    // flags: 0 = key down by virtual key, 2 = key up, 4 = unicode char down, 6 = unicode char up
    public static uint SendKey(ushort vk, ushort scan, uint flags)
    {
        INPUT[] a = new INPUT[1];
        a[0].type = 1;
        a[0].u.ki.wVk = vk;
        a[0].u.ki.wScan = scan;
        a[0].u.ki.dwFlags = flags;
        return SendInput(1, a, Marshal.SizeOf(typeof(INPUT)));
    }

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, EntryPoint = "NCryptOpenStorageProvider")]
    static extern int ProbeOpen(out IntPtr phProvider, string pszProviderName, uint dwFlags);
    [DllImport("ncrypt.dll", EntryPoint = "NCryptFreeObject")]
    static extern int ProbeFree(IntPtr hObject);

    public static string OpenProvider(string provider)
    {
        IntPtr h;
        int hr = ProbeOpen(out h, provider, 0);
        if (hr == 0) ProbeFree(h);
        return "0x" + ((uint)hr).ToString("X8");
    }

    // --- Windows Biometric Framework: which biometric types are enrolled for this user ---
    [DllImport("winbio.dll")]
    static extern int WinBioGetEnrolledFactors(byte[] accountOwner, out uint enrolledFactors);

    public static int GetEnrolledFactors(byte[] sid, out uint factors)
    {
        byte[] id = new byte[76];
        BitConverter.GetBytes(3).CopyTo(id, 0);          // WINBIO_ID_TYPE_SID
        BitConverter.GetBytes(sid.Length).CopyTo(id, 4); // AccountSid.Size
        Array.Copy(sid, 0, id, 8, sid.Length);           // AccountSid.Data
        return WinBioGetEnrolledFactors(id, out factors);
    }
}
'@

function Initialize-Native {
    if (-not ('HsKey' -as [type])) { Add-Type -TypeDefinition $script:CSharp -Language CSharp }
    Add-Type -AssemblyName System.Security
}

$script:ProvNgc = 'Microsoft Passport Key Storage Provider'
$script:ProvPcp = 'Microsoft Platform Crypto Provider'

# ---------------------------------------------------------------------------
# Key agreement helper for S11. A separate compile unit on purpose: it is compiled only when S11
# runs, so a problem in it can fail S11 and nothing else.
# ---------------------------------------------------------------------------
$script:CSharpAgree = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class HsAgree
{
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);
    [DllImport("ncrypt.dll")]
    static extern int NCryptFinalizeKey(IntPtr hKey, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptExportKey(IntPtr hKey, IntPtr hExportKey, string pszBlobType, IntPtr pParameterList, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptImportKey(IntPtr hProvider, IntPtr hImportKey, string pszBlobType, IntPtr pParameterList, out IntPtr phKey, byte[] pbData, int cbData, uint dwFlags);
    [DllImport("ncrypt.dll")]
    static extern int NCryptSecretAgreement(IntPtr hPrivKey, IntPtr hPubKey, out IntPtr phAgreedSecret, uint dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    static extern int NCryptDeriveKey(IntPtr hSharedSecret, string pwszKDF, IntPtr pParameterList, byte[] pbDerivedKey, int cbDerivedKey, out int pcbResult, uint dwFlags);
    [DllImport("ncrypt.dll")]
    static extern int NCryptFreeObject(IntPtr hObject);

    // bcrypt.h: KDF_HASH_ALGORITHM = 0, KDF_HKDF_SALT = 0x13, KDF_HKDF_INFO = 0x14.
    const int KDF_HASH_ALGORITHM = 0;
    const int KDF_HKDF_INFO = 0x14;

    public string Provider;
    public string Name;
    public IntPtr HProv = IntPtr.Zero;
    public IntPtr HKey = IntPtr.Zero;
    public List<string> Log = new List<string>();
    public int LastHr;
    public byte[] LastDerived;

    public static string Hex(int hr) { return "0x" + ((uint)hr).ToString("X8"); }

    int Step(string what, int hr) { Log.Add(what + "=" + Hex(hr)); LastHr = hr; return hr; }

    // An ECDH_P256 key with NO user interface policy and NO Windows Hello gesture. name null makes an ephemeral key.
    public int Create(string provider, string name)
    {
        Provider = provider;
        Name = name;
        int hr = Step("openProvider", NCryptOpenStorageProvider(out HProv, provider, 0));
        if (hr != 0) return hr;
        hr = Step("createPersistedKey", NCryptCreatePersistedKey(HProv, out HKey, "ECDH_P256", name, 0, 0));
        if (hr != 0) return hr;
        return Step("finalize", NCryptFinalizeKey(HKey, 0));
    }

    public byte[] GetBytes(string prop)
    {
        int cb;
        int hr = NCryptGetProperty(HKey, prop, null, 0, out cb, 0);
        LastHr = hr;
        if (hr != 0) return null;
        byte[] b = new byte[cb];
        hr = NCryptGetProperty(HKey, prop, b, cb, out cb, 0);
        LastHr = hr;
        if (hr != 0) return null;
        return b;
    }

    public long GetDword(string prop)
    {
        byte[] b = GetBytes(prop);
        if (b == null || b.Length < 4) return -1;
        return BitConverter.ToUInt32(b, 0);
    }

    public string GetStr(string prop)
    {
        byte[] b = GetBytes(prop);
        if (b == null) return null;
        return Encoding.Unicode.GetString(b).TrimEnd('\0');
    }

    public string Probe(string prop)
    {
        int cb;
        int hr = NCryptGetProperty(HKey, prop, null, 0, out cb, 0);
        return Hex(hr) + " size=" + cb;
    }

    public byte[] ExportPublic()
    {
        int cb;
        int hr = NCryptExportKey(HKey, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, null, 0, out cb, 0);
        LastHr = hr;
        if (hr != 0) return null;
        byte[] b = new byte[cb];
        hr = NCryptExportKey(HKey, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, b, cb, out cb, 0);
        LastHr = hr;
        if (hr != 0) return null;
        return b;
    }

    // BCryptBufferDesc { ULONG ulVersion; ULONG cBuffers; PBCryptBuffer pBuffers; } and one
    // BCryptBuffer { ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer; } per entry.
    static IntPtr BuildParameters(List<int> types, List<byte[]> values, List<IntPtr> toFree)
    {
        int ps = IntPtr.Size;
        int entry = 8 + ps;
        IntPtr buffers = Marshal.AllocHGlobal(entry * types.Count);
        toFree.Add(buffers);
        for (int i = 0; i < types.Count; i++)
        {
            IntPtr data = Marshal.AllocHGlobal(values[i].Length == 0 ? 1 : values[i].Length);
            toFree.Add(data);
            if (values[i].Length > 0) Marshal.Copy(values[i], 0, data, values[i].Length);
            Marshal.WriteInt32(buffers, i * entry, values[i].Length);
            Marshal.WriteInt32(buffers, i * entry + 4, types[i]);
            Marshal.WriteIntPtr(buffers, i * entry + 8, data);
        }
        IntPtr desc = Marshal.AllocHGlobal(8 + ps);
        toFree.Add(desc);
        Marshal.WriteInt32(desc, 0, 0);
        Marshal.WriteInt32(desc, 4, types.Count);
        Marshal.WriteIntPtr(desc, 8, buffers);
        return desc;
    }

    // ECDH between this key and the public blob of another key, then a derivation inside the same call chain.
    // importProvider: where the other key's public half is imported. kdf: "HKDF" (SHA-256, info) or "HASH" (SHA-256).
    // flags 0x40 is NCRYPT_SILENT_FLAG: the call fails instead of showing a window.
    public int AgreeAndDerive(byte[] peerPublicBlob, string importProvider, string kdf, byte[] info, uint flags)
    {
        LastDerived = null;
        IntPtr hImp = IntPtr.Zero, hPeer = IntPtr.Zero, hSecret = IntPtr.Zero;
        List<IntPtr> toFree = new List<IntPtr>();
        try
        {
            int hr = Step("openImportProvider", NCryptOpenStorageProvider(out hImp, importProvider, 0));
            if (hr != 0) return hr;
            hr = Step("importPeerPublic", NCryptImportKey(hImp, IntPtr.Zero, "ECCPUBLICBLOB", IntPtr.Zero, out hPeer, peerPublicBlob, peerPublicBlob.Length, 0));
            if (hr != 0) return hr;
            hr = Step("secretAgreement", NCryptSecretAgreement(HKey, hPeer, out hSecret, flags));
            if (hr != 0) return hr;
            List<int> types = new List<int>();
            List<byte[]> values = new List<byte[]>();
            types.Add(KDF_HASH_ALGORITHM);
            values.Add(Encoding.Unicode.GetBytes("SHA256\0"));
            if (kdf == "HKDF") { types.Add(KDF_HKDF_INFO); values.Add(info); }
            IntPtr parameters = BuildParameters(types, values, toFree);
            int cb;
            byte[] output = new byte[32];
            hr = Step("deriveKey_" + kdf, NCryptDeriveKey(hSecret, kdf, parameters, output, output.Length, out cb, 0));
            if (hr != 0) return hr;
            LastDerived = new byte[cb];
            Array.Copy(output, LastDerived, cb);
            return 0;
        }
        finally
        {
            foreach (IntPtr p in toFree) Marshal.FreeHGlobal(p);
            if (hSecret != IntPtr.Zero) NCryptFreeObject(hSecret);
            if (hPeer != IntPtr.Zero) NCryptFreeObject(hPeer);
            if (hImp != IntPtr.Zero) NCryptFreeObject(hImp);
        }
    }

    public void Close()
    {
        if (HKey != IntPtr.Zero) { NCryptFreeObject(HKey); HKey = IntPtr.Zero; }
        if (HProv != IntPtr.Zero) { NCryptFreeObject(HProv); HProv = IntPtr.Zero; }
    }
}
'@

function Initialize-Agree {
    if (-not ('HsAgree' -as [type])) { Add-Type -TypeDefinition $script:CSharpAgree -Language CSharp }
}

function Get-Digest([string]$text) {
    [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($text))
}

# ---------------------------------------------------------------------------
# Child mode: sign once with a named key, print one JSON line, exit.
# Used to test a prompt raised by a process with piped stdio and no window.
# ---------------------------------------------------------------------------
if ($ChildSign) {
    Initialize-Native
    $ck = New-Object HsKey
    $chr = $ck.Open($ChildProvider, $ChildSign)
    if ($chr -eq 0) {
        $ck.SetHwnd()
        $chr = $ck.Sign((Get-Digest 'handsal-spike-child'), 0)
    }
    $len = 0
    if ($ck.LastSig) { $len = $ck.LastSig.Length }
    $ck.Close()
    $o = @{ hr = [HsKey]::Hex($chr); sigLen = $len; log = @($ck.Log) }
    Write-Output ($o | ConvertTo-Json -Compress)
    exit 0
}

# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------
Initialize-Native

$script:Steps = New-Object System.Collections.ArrayList
$script:Created = New-Object System.Collections.ArrayList
$script:Main = $null
$script:Kcm = $null
$script:KcmName = $null
$script:WinRt = $false
$script:Started = (Get-Date).ToUniversalTime().ToString('o')
$script:SidText = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$script:Rand = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$script:Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:ReportPath = Join-Path (Get-Location).Path 'handsal-spike-report.json'
$script:ScratchDirs = New-Object System.Collections.ArrayList

function ToHex([byte[]]$b) { if ($null -eq $b) { return $null }; (($b | ForEach-Object { $_.ToString('x2') }) -join '') }
function B64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
function Redact([string]$s) { if ($null -eq $s) { return $s }; $s.Replace($script:SidText, '<SID>') }

function Ask([string]$question, [string[]]$valid) {
    while ($true) {
        $a = (Read-Host $question).Trim().ToLower()
        if ($valid -contains $a) { return $a }
        Write-Host ('Please answer one of: ' + ($valid -join ', '))
    }
}

function Pause-Ready([string]$msg) { [void](Read-Host ($msg + ' (press Enter when ready)')) }

# Invariant: every value that is recorded is plain data: a string, a number, a bool, null, a dictionary
# with string keys, or an array, whose members are plain data too. Anything else (a PSCustomObject, a .NET
# or WinRT object, an enum) can have a deep or cyclic graph that ConvertTo-Json on Windows PowerShell 5.1
# walks forever, so it is refused where it is recorded, not where it is serialized.
# Returns $null when $value is plain, else one line naming the first path and .NET type that is not.
# Needs nothing from the Windows parts of this script (test-plain-data.ps1 runs it alone).
function Find-NonPlainData($value, [string]$path, [int]$maxDepth, [int]$depth = 0, $ancestors = $null) {
    if ($null -eq $value) { return $null }
    if ($value -is [string] -or $value -is [bool]) { return $null }
    if ($value -is [sbyte] -or $value -is [byte] -or $value -is [int16] -or $value -is [uint16] -or
        $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64] -or
        $value -is [single] -or $value -is [double] -or $value -is [decimal]) { return $null }
    $isDict = $value -is [System.Collections.IDictionary]
    $isList = ($value -is [System.Collections.IList]) -and -not $isDict
    if (-not ($isDict -or $isList)) {
        return ('{0}: {1} is not plain data' -f $path, $value.GetType().FullName)
    }
    if ($depth -ge $maxDepth) { return ('{0}: nested deeper than {1} levels' -f $path, $maxDepth) }
    if ($null -eq $ancestors) { $ancestors = New-Object System.Collections.ArrayList }
    foreach ($a in $ancestors) {
        if ([object]::ReferenceEquals($a, $value)) { return ('{0}: cycle, {1} contains itself' -f $path, $value.GetType().FullName) }
    }
    [void]$ancestors.Add($value)
    try {
        if ($isDict) {
            foreach ($k in @($value.Keys)) {
                if ($k -isnot [string]) { return ('{0}: dictionary key of type {1} is not a string' -f $path, $k.GetType().FullName) }
                $p = Find-NonPlainData $value[$k] ($path + '.' + $k) $maxDepth ($depth + 1) $ancestors
                if ($null -ne $p) { return $p }
            }
        }
        else {
            for ($i = 0; $i -lt $value.Count; $i++) {
                $p = Find-NonPlainData $value[$i] ('{0}[{1}]' -f $path, $i) $maxDepth ($depth + 1) $ancestors
                if ($null -ne $p) { return $p }
            }
        }
    }
    finally { $ancestors.RemoveAt($ancestors.Count - 1) }
    return $null
}

function Run-Step([string]$id, [string]$assumption, [scriptblock]$body) {
    Write-Host ''
    Write-Host ("=== {0}: {1}" -f $id, $assumption) -ForegroundColor Cyan
    $res = $null
    try {
        $out = @(& $body) | Where-Object { $_ -is [System.Collections.IDictionary] } | Select-Object -Last 1
        if ($null -eq $out) { $out = @{ result = 'error'; evidence = @{ detail = 'step returned nothing' } } }
        $res = $out
    }
    catch {
        $res = @{ result = 'error'; evidence = @{ exception = $_.Exception.Message } }
    }
    # The one place evidence enters the report. Depth 8 leaves room under the report's ConvertTo-Json depth.
    $bad = Find-NonPlainData $res.evidence 'evidence' 8
    if ($null -eq $bad) { $bad = Find-NonPlainData $res.result 'result' 1 }
    if ($null -eq $bad) { $bad = Find-NonPlainData $res.note 'note' 1 }
    if ($null -ne $bad) {
        Write-Host ("    Evidence of step {0} refused: {1}" -f $id, $bad) -ForegroundColor Red
        $res = @{ result = 'error'; evidence = @{ evidence_refused = $bad } }
    }
    $rec = [ordered]@{
        step       = $id
        assumption = $assumption
        result     = $res.result
        evidence   = $res.evidence
        note       = $res.note
        at         = (Get-Date).ToUniversalTime().ToString('o')
    }
    [void]$script:Steps.Add($rec)
    $color = 'Yellow'
    if ($rec.result -eq 'yes') { $color = 'Green' } elseif ($rec.result -eq 'no') { $color = 'Red' }
    Write-Host ("--> {0}: {1}" -f $id, $rec.result.ToUpper()) -ForegroundColor $color
    if ($rec.note) { Write-Host ("    " + $rec.note) }
}

function Get-StepResult([string]$id) {
    $s = $script:Steps | Where-Object { $_.step -eq $id } | Select-Object -First 1
    if ($s) { return $s.result }
    return 'not_run'
}

function Register-Key([string]$provider, [string]$name) {
    [void]$script:Created.Add(@{ kind = 'ncrypt'; provider = $provider; name = $name })
}

function UInt([int]$hr) { [BitConverter]::ToUInt32([BitConverter]::GetBytes($hr), 0) }
function IsCancelHr([int]$hr) {
    $u = UInt $hr
    return ($u -eq 0x80090036 -or $u -eq 0x800704C7 -or $u -eq 0x8010006E)
}

function Invoke-Sign($key, [byte[]]$digest, [uint32]$flags) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $hr = $key.Sign($digest, $flags)
    $sw.Stop()
    return @{ hr = $hr; hex = [HsKey]::Hex($hr); sig = $key.LastSig; ms = $sw.ElapsedMilliseconds }
}

function Get-PubParts($key) {
    $blob = $key.ExportPublic()
    if ($null -eq $blob -or $blob.Length -lt 72) { return $null }
    $x = New-Object byte[] 32; $y = New-Object byte[] 32
    [Array]::Copy($blob, 8, $x, 0, 32); [Array]::Copy($blob, 40, $y, 0, 32)
    return @{ blob = $blob; x = $x; y = $y; magic = ('0x{0:X8}' -f [BitConverter]::ToUInt32($blob, 0)) }
}

function Test-Sig([byte[]]$pubBlob, [byte[]]$digest, [byte[]]$sig) {
    try {
        $ck = [Security.Cryptography.CngKey]::Import($pubBlob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
        $ec = New-Object Security.Cryptography.ECDsaCng($ck)
        return [bool]$ec.VerifyHash($digest, $sig)
    }
    catch { return $false }
}

# --- WinRT access (Windows PowerShell 5.1) ---
function Initialize-WinRt {
    try {
        $null = [Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType = WindowsRuntime]
        $null = [Windows.Security.Credentials.KeyCredentialCreationOption, Windows.Security.Credentials, ContentType = WindowsRuntime]
        $null = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $m = [System.WindowsRuntimeSystemExtensions].GetMethods()
        $script:AsTaskGen = $m | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
        $script:AsTaskAct = $m | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' } | Select-Object -First 1
        $script:WinRt = $true
    }
    catch { $script:WinRt = $false; $script:WinRtError = $_.Exception.Message }
}
function Wait-Op($op, [Type]$resultType, [int]$ms = 180000) {
    $task = $script:AsTaskGen.MakeGenericMethod($resultType).Invoke($null, @($op))
    if (-not $task.Wait($ms)) { throw 'WinRT call timed out' }
    return $task.Result
}
function Wait-Act($act, [int]$ms = 60000) {
    $task = $script:AsTaskAct.Invoke($null, @($act))
    [void]$task.Wait($ms)
}
function To-IBuffer([byte[]]$b) { [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::AsBuffer($b) }
function From-IBuffer($buf) { [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::ToArray($buf) }

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
function Step-S0 {
    $ev = [ordered]@{}
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $ev.os = [ordered]@{
        product = $cv.ProductName; display_version = $cv.DisplayVersion
        build = $cv.CurrentBuild; ubr = $cv.UBR; is64 = [Environment]::Is64BitOperatingSystem
    }
    $ev.powershell = $PSVersionTable.PSVersion.ToString()
    $ev.elevated = $script:Elevated

    $tpm = [ordered]@{}
    try { $t = Get-Tpm; $tpm.get_tpm = @{ present = $t.TpmPresent; ready = $t.TpmReady; manufacturer = $t.ManufacturerIdTxt; manufacturer_version = $t.ManufacturerVersion } }
    catch { $tpm.get_tpm_error = $_.Exception.Message }
    try { $w = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm; if ($w) { $tpm.win32_tpm = @{ spec_version = $w.SpecVersion; enabled = $w.IsEnabled_InitialValue; activated = $w.IsActivated_InitialValue } } else { $tpm.win32_tpm = 'no instance' } }
    catch { $tpm.win32_tpm_error = $_.Exception.Message }
    $ev.tpm = $tpm

    $prov = [ordered]@{}
    foreach ($p in @($script:ProvNgc, $script:ProvPcp)) {
        $hr = [HsUtil]::OpenProvider($p)
        $prov[$p] = $hr
    }
    $ev.providers_open = $prov

    $hello = [ordered]@{ winrt_available = $script:WinRt }
    if ($script:WinRt) {
        try { $hello.key_credential_supported = [bool](Wait-Op ([Windows.Security.Credentials.KeyCredentialManager]::IsSupportedAsync()) ([bool])) } catch { $hello.key_credential_supported_error = $_.Exception.Message }
        try { $hello.consent_verifier_availability = [string](Wait-Op ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])) } catch { $hello.consent_verifier_error = $_.Exception.Message }
    }
    $ev.hello = $hello

    $bio = [ordered]@{}
    try {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $sb = New-Object byte[] $sid.BinaryLength
        $sid.GetBinaryForm($sb, 0)
        $f = [uint32]0
        $hr = [HsUtil]::GetEnrolledFactors($sb, [ref]$f)
        $bio.winbio_hr = [HsKey]::Hex($hr)
        $bio.winbio_factor_mask = ('0x{0:X}' -f $f)
        $bio.fingerprint_enrolled = [bool]($f -band 0x8)
        $bio.face_enrolled = [bool]($f -band 0x2)
        $bio.iris_enrolled = [bool]($f -band 0x10)
    }
    catch { $bio.winbio_error = $_.Exception.Message }
    try { $bio.biometric_devices = @(Get-PnpDevice -Class Biometric -PresentOnly -ErrorAction Stop | ForEach-Object { $_.FriendlyName }) } catch { $bio.biometric_devices_error = $_.Exception.Message }
    try { $bio.ir_or_hello_cameras = @(Get-PnpDevice -Class Camera -PresentOnly -ErrorAction Stop | Where-Object { $_.FriendlyName -match 'IR|Infrared|Hello' } | ForEach-Object { $_.FriendlyName }) } catch { $bio.cameras_error = $_.Exception.Message }
    try {
        $ds = & dsregcmd.exe /status 2>&1 | Select-String -Pattern 'NgcSet'
        $bio.pin_set_dsregcmd = if ($ds) { ($ds.Line.Trim()) } else { 'NgcSet line not found' }
    }
    catch { $bio.pin_set_error = $_.Exception.Message }
    $bio.pin_note = 'Windows Hello requires a PIN before any fingerprint or face can be enrolled, so any enrolled biometric implies a PIN exists.'
    $ev.hello_methods = $bio

    $ess = [ordered]@{}
    $ess.script_can_read_state = $false
    $ess.note = 'No documented API found for Enhanced Sign-in Security state. Recorded as a human answer below.'
    try { $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics' -ErrorAction Stop; $ess.biometrics_policy_key = ($pol | Select-Object * -ExcludeProperty PS*) } catch { $ess.biometrics_policy_key = 'absent' }
    $a = Ask 'Does Settings > Accounts > Sign-in options show "Sign in with an external camera or fingerprint reader"? (y / n / u = unsure)' @('y', 'n', 'u')
    $ess.human_external_camera_setting_visible = $a
    $ev.enhanced_sign_in_security = $ess

    $ok = ($prov.Values | Where-Object { $_ -eq '0x00000000' }).Count -gt 0
    return @{ result = $(if ($ok) { 'yes' } else { 'no' }); evidence = $ev; note = 'Inventory only. yes means at least one hardware-capable key provider could be opened.' }
}

function Step-S1 {
    $ev = [ordered]@{ attempts = @() }
    $sid = $script:SidText
    $attempts = @(
        @{ id = 'A1_passport_plain_name'; prov = $script:ProvNgc; name = ('handsal-spike-' + $script:Rand); ui = -1 },
        @{ id = 'A2_passport_sid_form_name'; prov = $script:ProvNgc; name = ($sid + '//handsal-spike//' + $script:Rand); ui = -1 },
        @{ id = 'B_platform_crypto_ui_policy'; prov = $script:ProvPcp; name = ('handsal-spike-pcp-' + $script:Rand); ui = 3 }
    )
    $ngcDone = $false
    foreach ($a in $attempts) {
        if ($a.id -eq 'A2_passport_sid_form_name' -and $ngcDone) {
            $ev.attempts += [ordered]@{ id = $a.id; skipped = 'A1 already succeeded' }
            continue
        }
        Write-Host ("Trying " + $a.id + " (a Windows prompt may appear)") -ForegroundColor DarkGray
        $k = New-Object HsKey
        $hr = $k.Create($a.prov, $a.name, $a.ui, -1, $true, $false)
        $rec = [ordered]@{ id = $a.id; provider = $a.prov; hr = [HsKey]::Hex($hr); log = @($k.Log); applied = @($k.Applied); rejected = @($k.Rejected) }
        if ($hr -eq 0) {
            Register-Key $a.prov $a.name
            $rec.algorithm = $k.GetStr('Algorithm Name')
            $rec.algorithm_group = $k.GetStr('Algorithm Group')
            $rec.length_bits = $k.GetDword('Length')
            $impl = $k.GetDword('Impl Type')
            $rec.impl_type = $impl
            $rec.hardware = ($impl -ge 0 -and (($impl -band 1) -eq 1))
            $rec.export_policy = $k.GetDword('Export Policy')
            $p256 = ($rec.algorithm -eq 'ECDSA_P256' -or $rec.length_bits -eq 256)
            $rec.p256 = $p256
            if ($a.id -like 'A*') { $ngcDone = $true }
            if ($null -eq $script:Main -and $p256) { $script:Main = $k; $rec.selected_for_later_steps = $true }
            else { $k.Close() }
        }
        else { $k.Close() }
        $ev.attempts += $rec
    }

    $kc = [ordered]@{}
    if ($script:WinRt) {
        try {
            $script:KcmName = 'handsal-spike-kcm-' + $script:Rand
            Write-Host 'Trying C_winrt_key_credential_manager (a Windows prompt will appear)' -ForegroundColor DarkGray
            $r = Wait-Op ([Windows.Security.Credentials.KeyCredentialManager]::RequestCreateAsync($script:KcmName, [Windows.Security.Credentials.KeyCredentialCreationOption]::ReplaceExisting)) ([Windows.Security.Credentials.KeyCredentialRetrievalResult])
            $kc.status = [string]$r.Status
            if ([string]$r.Status -eq 'Success') {
                [void]$script:Created.Add(@{ kind = 'winrt'; provider = 'KeyCredentialManager'; name = $script:KcmName })
                $script:Kcm = $r.Credential
                $spki = From-IBuffer ($r.Credential.RetrievePublicKey())
                $kc.spki_length = $spki.Length
                $hex = ToHex $spki
                $kc.algorithm = if ($hex -like '*2a864886f70d010101*') { 'RSA' } elseif ($hex -like '*2a8648ce3d0201*') { 'EC' } else { 'unknown' }
                $kc.attestation_status_property = 'not requested'
            }
        }
        catch { $kc.error = $_.Exception.Message }
    }
    else { $kc.skipped = 'WinRT not available' }
    $ev.winrt_key_credential_manager = $kc

    $good = @($ev.attempts | Where-Object { $_.hr -eq '0x00000000' -and $_.p256 -eq $true })
    $hw = @($good | Where-Object { $_.hardware -eq $true })
    $note = ''
    if ($hw.Count -gt 0) { $res = 'yes' } else { $res = 'no'; $note = 'No P-256 key with the hardware implementation flag could be created.' }
    if ($good.Count -gt 0 -and $hw.Count -eq 0) { $note = 'A P-256 key was created but the provider did not report a hardware implementation.' }
    return @{ result = $res; evidence = $ev; note = $note }
}

function Step-S2 {
    if ($null -eq $script:Main) { return @{ result = 'skipped'; evidence = @{ reason = 'no NCrypt key from S1' } } }
    $k = $script:Main
    $ev = [ordered]@{}
    $ev.export_policy_property = $k.GetDword('Export Policy')
    $ev.export_policy_read_hr = [HsKey]::Hex($k.LastHr)
    $exp = [ordered]@{}
    foreach ($bt in @('ECCPRIVATEBLOB', 'ECCFULLPRIVATEBLOB', 'PKCS8_PRIVATEKEY', 'PRIVATEBLOB')) {
        $hr = $k.TryExportPrivate($bt)
        $exp[$bt] = [HsKey]::Hex($hr)
    }
    $ev.private_export_attempts = $exp
    $ev.public_export_ok = ($null -ne $k.ExportPublic())
    $anyOk = @($exp.Values | Where-Object { $_ -eq '0x00000000' }).Count -gt 0
    return @{ result = $(if ($anyOk) { 'no' } else { 'yes' }); evidence = $ev; note = 'yes means every private-key export was refused.' }
}

function Step-S3 {
    if ($null -eq $script:Main) { return @{ result = 'skipped'; evidence = @{ reason = 'no NCrypt key from S1' } } }
    $k = $script:Main
    $hdr = '{"alg":"ES256","kid":"spike-1"}'
    $pay = '{"handsal":"spike"}'
    $si = (B64Url ([Text.Encoding]::UTF8.GetBytes($hdr))) + '.' + (B64Url ([Text.Encoding]::UTF8.GetBytes($pay)))
    $digest = Get-Digest $si
    $pub = Get-PubParts $k
    Write-Host 'A Windows prompt should appear now. Approve it with your fingerprint or face.' -ForegroundColor Yellow
    $r = Invoke-Sign $k $digest 0
    $ev = [ordered]@{ sign_hr = $r.hex; elapsed_ms = $r.ms; signing_input = $si; digest_sha256 = (ToHex $digest) }
    $ev.human_saw_prompt = Ask 'Did a Windows prompt appear for that signature? (y / n)' @('y', 'n')
    if ($pub) { $ev.public_key = [ordered]@{ blob_magic = $pub.magic; x = (ToHex $pub.x); y = (ToHex $pub.y) } }
    if ($r.hr -ne 0 -or $null -eq $r.sig) { return @{ result = 'no'; evidence = $ev; note = 'Signing failed.' } }
    $sig = $r.sig
    $ev.signature_length = $sig.Length
    $ev.first_byte = ('0x{0:X2}' -f $sig[0])
    $raw = $null
    if ($sig.Length -eq 64) { $ev.format = 'raw_r_s_64'; $raw = $sig }
    else {
        $d = [HsUtil]::DerToRaw($sig)
        if ($d) { $ev.format = 'der'; $raw = $d } else { $ev.format = 'unknown' }
    }
    if ($null -eq $raw) { return @{ result = 'no'; evidence = $ev; note = 'Signature is neither raw 64 bytes nor DER.' } }
    $ev.signature_hex = ToHex $raw
    $ev.raw_signature_was_high_s = [HsUtil]::IsHighS($raw)
    $low = [HsUtil]::ToLowS($raw)
    $ev.low_s_signature_hex = ToHex $low
    if ($pub) {
        $ev.verifies_as_returned = Test-Sig $pub.blob $digest $raw
        $ev.verifies_after_low_s = Test-Sig $pub.blob $digest $low
        $x = B64Url $pub.x; $y = B64Url $pub.y
        $ev.vitni_keys_json = '{"srv-ec":{"spike-1":{"alg":"ES256","crv":"P-256","kty":"EC","status":"active","x":"' + $x + '","y":"' + $y + '"}}}'
        $ev.jws = $si + '.' + (B64Url $low)
    }
    $ev.note_vitni = 'Not run here. The owner can feed jws and vitni_keys_json to vitni-verify-go later.'
    $pass = ($ev.format -eq 'raw_r_s_64') -and ($ev.verifies_after_low_s -eq $true) -and ($ev.verifies_as_returned -eq $true)
    return @{ result = $(if ($pass) { 'yes' } else { 'no' }); evidence = $ev; note = ('format=' + $ev.format + ', high-S before normalizing=' + $ev.raw_signature_was_high_s) }
}

function Step-S4 {
    if ($null -eq $script:Main) { return @{ result = 'skipped'; evidence = @{ reason = 'no NCrypt key from S1' } } }
    $k = $script:Main
    $pub = Get-PubParts $k
    $ev = [ordered]@{ signs = @() }
    Write-Host 'Four signatures follow, back to back. Expect a Windows prompt for each. Approve each one.' -ForegroundColor Yellow
    Pause-Ready 'Ready for four signatures'
    $total = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 1; $i -le 3; $i++) {
        $d = Get-Digest ("handsal-spike-s4-same-handle-" + $i)
        $r = Invoke-Sign $k $d 0
        $ev.signs += [ordered]@{ n = $i; handle = 'same'; hr = $r.hex; ms = $r.ms; verifies = $(if ($r.sig -and $pub) { Test-Sig $pub.blob $d $(if ($r.sig.Length -eq 64) { $r.sig } else { [HsUtil]::DerToRaw($r.sig) }) } else { $false }) }
    }
    $k2 = New-Object HsKey
    $hr2 = $k2.Open($k.Provider, $k.Name)
    if ($hr2 -eq 0) {
        $k2.SetHwnd()
        $d = Get-Digest 'handsal-spike-s4-new-handle-4'
        $r = Invoke-Sign $k2 $d 0
        $ev.signs += [ordered]@{ n = 4; handle = 'reopened'; hr = $r.hex; ms = $r.ms }
        $k2.Close()
    }
    else { $ev.signs += [ordered]@{ n = 4; handle = 'reopened'; open_hr = [HsKey]::Hex($hr2) } }
    $total.Stop()
    $ev.total_seconds = [math]::Round($total.Elapsed.TotalSeconds, 1)
    $ev.human_prompt_count = [int](Ask 'How many Windows prompts did you see for those four signatures? (0-6)' @('0', '1', '2', '3', '4', '5', '6'))
    $ev.human_prompt_text_visible = Ask 'Did the prompt show any message text from the app (for example "handsal spike")? (y / n / u)' @('y', 'n', 'u')

    $sd = Invoke-Sign $k (Get-Digest 'handsal-spike-s4-silent') 0x40
    $ev.silent_call = [ordered]@{ flag = 'NCRYPT_SILENT_FLAG 0x40'; hr = $sd.hex; produced_signature = ($null -ne $sd.sig) }
    $signedCount = @($ev.signs | Where-Object { $_.hr -eq '0x00000000' }).Count
    $pass = ($ev.human_prompt_count -eq 4) -and ($signedCount -eq 4) -and ($sd.hr -ne 0)
    return @{ result = $(if ($pass) { 'yes' } else { 'no' }); evidence = $ev; note = 'yes needs four prompts for four signatures and a silent call that fails.' }
}

function Step-S5 {
    if ($null -eq $script:Main) { return @{ result = 'skipped'; evidence = @{ reason = 'no NCrypt key from S1' } } }
    $k = $script:Main
    $ev = [ordered]@{}
    $props = [ordered]@{}
    foreach ($p in @('UI Policy', 'Use Context', 'HWND Handle', 'NgcCacheType', 'NgcCacheTypeProperty', 'PinCacheIsGestureRequired', 'PinCacheRequireGesture', 'Impl Type', 'Export Policy', 'Key Usage', 'Key Type', 'Unique Name', 'Algorithm Group', 'Algorithm Name', 'Length')) {
        $props[$p] = $k.Probe($p)
    }
    $ev.property_probe_on_main_key = $props
    $ev.pin_cache_is_gesture_required = $k.GetDword('PinCacheIsGestureRequired')
    $ev.ngc_cache_type = $k.GetDword('NgcCacheType')
    $ev.human_pin_option_visible = Ask 'At the earlier prompts, was a PIN option visible (a PIN button, "More choices" or "Sign-in options")? (y / n / u)' @('y', 'n', 'u')
    $ev.note = 'Property presence only. The behaviour test is S10.'
    $r = switch ($ev.human_pin_option_visible) { 'y' { 'yes' } 'n' { 'no' } default { 'skipped' } }
    return @{ result = $r; evidence = $ev; note = 'yes means a PIN path was offered at the default prompt.' }
}

function Step-S6 {
    if ($null -eq $script:Main) { return @{ result = 'skipped'; evidence = @{ reason = 'no NCrypt key from S1' } } }
    if (-not $IncludeEnrollmentChange) { return @{ result = 'skipped'; evidence = @{ reason = 'optional, run with -IncludeEnrollmentChange' }; note = 'Not gating.' } }
    $k = $script:Main
    $pub = Get-PubParts $k
    Write-Host 'Add one more fingerprint (or re-enroll your face) in Settings > Accounts > Sign-in options, then come back.' -ForegroundColor Yellow
    Pause-Ready 'Enrollment changed'
    $d = Get-Digest 'handsal-spike-s6'
    $r = Invoke-Sign $k $d 0
    $ev = [ordered]@{ hr = $r.hex; still_usable = ($r.hr -eq 0) }
    if ($r.sig -and $pub -and $r.sig.Length -eq 64) { $ev.verifies = Test-Sig $pub.blob $d $r.sig }
    return @{ result = $(if ($r.hr -eq 0) { 'yes' } else { 'no' }); evidence = $ev; note = 'yes means the key survived an enrollment change. Not gating.' }
}

function Step-S7 {
    if ($null -eq $script:Main) { return @{ result = 'skipped'; evidence = @{ reason = 'no NCrypt key from S1' } } }
    Write-Host 'On the next prompt, CANCEL it (click Cancel or press Esc).' -ForegroundColor Yellow
    Pause-Ready 'Ready to cancel one prompt'
    $r = Invoke-Sign $script:Main (Get-Digest 'handsal-spike-s7') 0
    $ev = [ordered]@{ hr = $r.hex; produced_signature = ($null -ne $r.sig); recognized_as_cancel = (IsCancelHr $r.hr) }
    if ($r.hr -eq 0) { return @{ result = 'skipped'; evidence = $ev; note = 'A signature was produced, so the prompt was not cancelled. Not gating.' } }
    return @{ result = $(if ($null -eq $r.sig) { 'yes' } else { 'no' }); evidence = $ev; note = 'yes means cancelling gave no signature and an error code. Not gating.' }
}

function Step-S8 {
    if ($null -eq $script:Main) { return @{ result = 'skipped'; evidence = @{ reason = 'no NCrypt key from S1' } } }
    $ev = [ordered]@{}
    $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $ps51
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -ChildSign "' + $script:Main.Name + '" -ChildProvider "' + $script:Main.Provider + '"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    Write-Host 'A second hidden process will now sign with stdin and stdout piped (like a call from WSL2). Watch for the prompt.' -ForegroundColor Yellow
    Pause-Ready 'Ready'
    $p = [Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $done = $p.WaitForExit(120000)
    $ev.child_exited = $done
    if ($done) {
        $out = $p.StandardOutput.ReadToEnd().Trim()
        $ev.child_exit_code = $p.ExitCode
        try { $ev.child_result = ($out | ConvertFrom-Json) } catch { $ev.child_stdout = $out }
        $ev.child_stderr_length = $p.StandardError.ReadToEnd().Length
    }
    else { try { $p.Kill() } catch { } }
    $ev.human_prompt_in_front = Ask 'Did the prompt appear in front of your other windows without you hunting for it? (y / n / none = no prompt appeared)' @('y', 'n', 'none')

    $wsl = [ordered]@{}
    if ($SkipWsl) { $wsl.skipped = 'switch -SkipWsl' }
    else {
        $wslExe = Join-Path $env:SystemRoot 'System32\wsl.exe'
        if (-not (Test-Path $wslExe)) { $wsl.skipped = 'wsl.exe not present' }
        else {
            foreach ($cmd in @(@{ n = 'distros'; a = '-l -q' }, @{ n = 'root_without_password'; a = '-u root whoami' })) {
                try {
                    $wp = New-Object Diagnostics.ProcessStartInfo
                    $wp.FileName = $wslExe; $wp.Arguments = $cmd.a
                    $wp.UseShellExecute = $false; $wp.RedirectStandardOutput = $true; $wp.RedirectStandardError = $true; $wp.CreateNoWindow = $true
                    $wp.StandardOutputEncoding = [Text.Encoding]::Unicode
                    $q = [Diagnostics.Process]::Start($wp)
                    if ($q.WaitForExit(20000)) { $wsl[$cmd.n] = [ordered]@{ exit = $q.ExitCode; stdout = ($q.StandardOutput.ReadToEnd().Trim() -replace "`0", '') } }
                    else { try { $q.Kill() } catch { }; $wsl[$cmd.n] = 'timed out after 20 s' }
                }
                catch { $wsl[$cmd.n] = 'error: ' + $_.Exception.Message }
            }
            $wsl.note = 'Run from Windows. The real test (exe called from inside WSL2) is not possible from PowerShell.'
        }
    }
    $ev.wsl = $wsl
    $childOk = ($ev.child_result -and $ev.child_result.hr -eq '0x00000000' -and $ev.child_result.sigLen -gt 0)
    $pass = $childOk -and ($ev.human_prompt_in_front -eq 'y')
    return @{ result = $(if ($pass) { 'yes' } else { 'no' }); evidence = $ev; note = 'yes means a piped, windowless process got a visible prompt and a signature. WSL2-side calling is untested.' }
}

function Step-S9 {
    $ev = [ordered]@{}
    $root = 'C:\ProgramData\handsal'
    $ev.real_path_exists = (Test-Path $root)
    if ($ev.real_path_exists) {
        try { $a = Get-Acl $root; $ev.real_path_owner = (Redact $a.Owner); $ev.real_path_inheritance_protected = $a.AreAccessRulesProtected } catch { $ev.real_path_acl_error = $_.Exception.Message }
    }
    try { $ev.programdata_icacls = @(& icacls.exe 'C:\ProgramData' 2>&1 | Select-Object -First 12 | ForEach-Object { Redact ([string]$_) }) } catch { $ev.programdata_icacls_error = $_.Exception.Message }
    if (-not $script:Elevated) {
        return @{ result = 'skipped'; evidence = $ev; note = 'Not elevated. Run PowerShell as Administrator to test the admin-only DACL. Not gating.' }
    }
    $dir = 'C:\ProgramData\handsal-spike-' + $script:Rand
    [void]$script:ScratchDirs.Add($dir)
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    [void](New-Item -ItemType Directory -Path ($dir + '\orgs') -Force)
    $setOk = $true
    foreach ($path in @($dir, ($dir + '\orgs'))) {
        try {
            $acl = New-Object Security.AccessControl.DirectorySecurity
            $acl.SetAccessRuleProtection($true, $false)
            $inh = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
            $none = [Security.AccessControl.PropagationFlags]::None
            $allow = [Security.AccessControl.AccessControlType]::Allow
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inh, $none, $allow)))
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admins, 'FullControl', $inh, $none, $allow)))
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', $inh, $none, $allow)))
            Set-Acl -Path $path -AclObject $acl
        }
        catch { $setOk = $false; $ev.set_acl_error = $_.Exception.Message }
    }
    $ev.dacl_applied = $setOk
    Set-Content -Path ($dir + '\orgs\test.pin') -Value 'handsal-spike' -Encoding ASCII
    try { $ev.icacls_orgs = @(& icacls.exe ($dir + '\orgs') 2>&1 | ForEach-Object { Redact ([string]$_) }) } catch { }

    # Run the write tests as a standard (non-elevated) token.
    $pub = $env:PUBLIC
    $cmdPath = Join-Path $pub ('hs' + $script:Rand + '.cmd')
    $resPath = Join-Path $pub ('hs' + $script:Rand + '.txt')
    $lines = @(
        '@echo off',
        'set P=%~1',
        'set R=%~2',
        'type "%P%\orgs\test.pin" >nul 2>nul',
        'if errorlevel 1 (echo read=blocked>>"%R%") else (echo read=ok>>"%R%")',
        '(echo x) > "%P%\orgs\new.txt" 2>nul',
        'if exist "%P%\orgs\new.txt" (echo create_file=SUCCEEDED>>"%R%") else (echo create_file=blocked>>"%R%")',
        '(echo changed) > "%P%\orgs\test.pin" 2>nul',
        'findstr /c:"changed" "%P%\orgs\test.pin" >nul 2>nul',
        'if errorlevel 1 (echo overwrite=blocked>>"%R%") else (echo overwrite=SUCCEEDED>>"%R%")',
        'ren "%P%\orgs\test.pin" renamed.pin 2>nul',
        'if exist "%P%\orgs\renamed.pin" (echo rename=SUCCEEDED>>"%R%") else (echo rename=blocked>>"%R%")',
        'del /q "%P%\orgs\test.pin" 2>nul',
        'if exist "%P%\orgs\test.pin" (echo delete=blocked>>"%R%") else (echo delete=SUCCEEDED>>"%R%")',
        'mkdir "%P%\sibling" 2>nul',
        'if exist "%P%\sibling" (echo create_dir_in_parent=SUCCEEDED>>"%R%") else (echo create_dir_in_parent=blocked>>"%R%")',
        'echo done>>"%R%"'
    )
    Set-Content -Path $cmdPath -Value $lines -Encoding ASCII
    if (Test-Path $resPath) { Remove-Item $resPath -Force }
    $line = 'cmd.exe /c ' + $cmdPath + ' ' + $dir + ' ' + $resPath
    try {
        & runas.exe /trustlevel:0x20000 $line | Out-Null
        $deadline = (Get-Date).AddSeconds(20)
        while ((Get-Date) -lt $deadline) {
            if ((Test-Path $resPath) -and ((Get-Content $resPath -Raw) -match 'done')) { break }
            Start-Sleep -Milliseconds 300
        }
        if (Test-Path $resPath) { $ev.standard_user_results = @(Get-Content $resPath | Where-Object { $_ -and $_ -ne 'done' }) }
        else { $ev.standard_user_results = 'no result file; runas /trustlevel may be blocked on this machine' }
    }
    catch { $ev.runas_error = $_.Exception.Message }
    Remove-Item $cmdPath, $resPath -Force -ErrorAction SilentlyContinue
    $res = @($ev.standard_user_results)
    $succeeded = @($res | Where-Object { $_ -match 'SUCCEEDED' })
    $haveRead = @($res | Where-Object { $_ -eq 'read=ok' }).Count -gt 0
    if (-not ($ev.standard_user_results -is [array])) {
        return @{ result = 'error'; evidence = $ev; note = 'Could not run the standard-user write tests. DACL was applied and listed.' }
    }
    $pass = $setOk -and $haveRead -and ($succeeded.Count -eq 0)
    return @{ result = $(if ($pass) { 'yes' } else { 'no' }); evidence = $ev; note = 'yes means the DACL applied, a standard user can read, and every write, rename, delete and create was refused. Not gating.' }
}

function Test-Config([string]$label, [scriptblock]$signer, [string[]]$knobs) {
    Write-Host ''
    Write-Host ("Config " + $label) -ForegroundColor Cyan
    if ($knobs.Count -gt 0) { Write-Host ("  app-level settings applied: " + ($knobs -join '; ')) }
    Write-Host '  A prompt will appear. TRY TO USE YOUR PIN: if you only see fingerprint or face, look for "More choices", "Sign-in options" or a PIN icon, then type your PIN.' -ForegroundColor Yellow
    Write-Host '  If there is no way to reach a PIN, do not guess: answer x below.' -ForegroundColor Yellow
    Pause-Ready 'Ready'
    $r = & $signer
    $ans = Ask 'What approved it? f = fingerprint or face, p = PIN, x = no PIN option was possible, n = no prompt appeared, c = I cancelled' @('f', 'p', 'x', 'n', 'c')
    return [ordered]@{ config = $label; app_level_settings_applied = @($knobs); sign_hr = $r.hr; produced_signature = [bool]$r.ok; ms = $r.ms; human_answer = $ans; pin_only_signature = ([bool]$r.ok -and $ans -eq 'p') }
}

function Step-S10 {
    $ev = [ordered]@{ configs = @(); knobs_enumerated = [ordered]@{} }
    $cfgs = New-Object System.Collections.ArrayList

    # Knobs the API surface offers, found by reflection and by property probing.
    if ($script:WinRt) {
        $ev.knobs_enumerated.KeyCredentialCreationOption_values = @([Enum]::GetNames([Windows.Security.Credentials.KeyCredentialCreationOption]))
        $ev.knobs_enumerated.KeyCredentialManager_methods = @([Windows.Security.Credentials.KeyCredentialManager].GetMethods() | Where-Object { $_.IsStatic } | ForEach-Object { $_.Name } | Sort-Object -Unique)
        $ev.knobs_enumerated.UserConsentVerifier_methods = @([Windows.Security.Credentials.UI.UserConsentVerifier].GetMethods() | Where-Object { $_.IsStatic } | ForEach-Object { $_.Name } | Sort-Object -Unique)
    }
    $ev.knobs_enumerated.note = 'NCrypt UI policy and Passport cache properties are applied per key below. WinBio can check a fingerprint in app code but that check is not bound to any key, so it cannot stand in for key-level enforcement.'

    $msg = 'This is the decisive test. You will approve several prompts. At each one, try the PIN.'
    Write-Host $msg -ForegroundColor Yellow
    $go = Ask 'Run S10 now? (y = yes, s = skip)' @('y', 's')
    if ($go -eq 's') { return @{ result = 'skipped'; evidence = $ev; note = 'Skipped by the user.' } }

    if ($script:Main) {
        $m = $script:Main
        $pub = Get-PubParts $m
        $sign = {
            $d = Get-Digest ('handsal-spike-s10-' + [Guid]::NewGuid().ToString('N'))
            $r = Invoke-Sign $script:Main $d 0
            $ok = ($r.hr -eq 0 -and $null -ne $r.sig)
            @{ hr = $r.hex; ok = $ok; ms = $r.ms }
        }
        [void]$cfgs.Add((Test-Config 'C0_default_key' $sign @()))

        $variants = @(
            @{ label = 'C1_ui_policy_protect_and_force_high'; ui = 3; g = -1 },
            @{ label = 'C2_pin_cache_require_gesture'; ui = -1; g = 1 }
        )
        foreach ($v in $variants) {
            $name = 'handsal-spike-' + $script:Rand + '-' + $v.label.Substring(0, 2).ToLower()
            $kv = New-Object HsKey
            $hr = $kv.Create($m.Provider, $name, $v.ui, $v.g, $true, $false)
            $knobs = @($kv.Applied | Where-Object { $_ -notlike 'HWND*' })
            $rec = [ordered]@{ config = $v.label; create_hr = [HsKey]::Hex($hr); applied = $knobs; rejected = @($kv.Rejected) }
            if ($hr -eq 0) { Register-Key $m.Provider $name }
            if ($hr -ne 0 -or $knobs.Count -eq 0) {
                $rec.tested = $false
                $rec.reason = 'knob rejected or key not created, so this would be the same as the default key'
                $ev.configs += $rec
                $kv.Close()
                continue
            }
            $script:CurKey = $kv
            $signv = {
                $d = Get-Digest ('handsal-spike-s10-' + [Guid]::NewGuid().ToString('N'))
                $r = Invoke-Sign $script:CurKey $d 0
                @{ hr = $r.hex; ok = ($r.hr -eq 0 -and $null -ne $r.sig); ms = $r.ms }
            }
            [void]$cfgs.Add((Test-Config $v.label $signv $knobs))
            $kv.Close()
        }
    }

    if ($script:WinRt) {
        $signU = {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $res = Wait-Op ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync('handsal spike: approve (try the PIN)')) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])
            @{ hr = [string]$res; ok = ([string]$res -eq 'Verified'); ms = $sw.ElapsedMilliseconds }
        }
        [void]$cfgs.Add((Test-Config 'UCV_user_consent_verifier' $signU @()))
        if ($script:Kcm) {
            $signK = {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $res = Wait-Op ($script:Kcm.RequestSignAsync((To-IBuffer (Get-Digest 'handsal-spike-s10-kcm')))) ([Windows.Security.Credentials.KeyCredentialOperationResult])
                @{ hr = [string]$res.Status; ok = ([string]$res.Status -eq 'Success'); ms = $sw.ElapsedMilliseconds }
            }
            [void]$cfgs.Add((Test-Config 'KCM_key_credential_manager' $signK @()))
        }
    }

    foreach ($c in $cfgs) { $ev.configs += $c }

    $c0 = $cfgs | Where-Object { $_.config -eq 'C0_default_key' } | Select-Object -First 1
    $knobCfgs = @($cfgs | Where-Object { $_.config -like 'C1*' -or $_.config -like 'C2*' })
    $anyPin = @($cfgs | Where-Object { $_.human_answer -eq 'p' }).Count -gt 0
    $anyNone = @($cfgs | Where-Object { $_.human_answer -eq 'x' }).Count -gt 0
    $defaultPin = ($c0 -and $c0.pin_only_signature)
    $knobRefused = @($knobCfgs | Where-Object { $_.human_answer -eq 'x' -and -not $_.produced_signature })
    $ev.analysis = [ordered]@{
        default_key_accepted_pin_only = [bool]$defaultPin
        knob_configs_tested = $knobCfgs.Count
        knob_configs_that_refused_pin = $knobRefused.Count
        any_config_accepted_pin_only = $anyPin
    }
    if (-not $anyPin -and -not $anyNone) {
        return @{ result = 'skipped'; evidence = $ev; note = 'No test showed either a working PIN or a refused PIN, so the question is unanswered.' }
    }
    if ($defaultPin -and $knobRefused.Count -gt 0) {
        return @{ result = 'yes'; evidence = $ev; note = 'An app-level setting made the PIN unusable where the default accepted it. Check which setting in analysis and repeat on a second machine.' }
    }
    $note = 'No app-level setting refused the PIN while the default accepted it.'
    if ($c0 -and $c0.human_answer -eq 'x') { $ev.analysis.system_level_biometric_only_seen = $true; $note = 'The PIN was unavailable even for the default key. That is a machine setting (for example Enhanced Sign-in Security), not something the app asked for, so it is not an API-level guarantee.' }
    return @{ result = 'no'; evidence = $ev; note = $note }
}

function Step-S10b {
    if ($SkipInjection) { return @{ result = 'skipped'; evidence = @{ reason = 'switch -SkipInjection' } } }
    if ($null -eq $script:Main) { return @{ result = 'skipped'; evidence = @{ reason = 'no NCrypt key from S1' } } }
    Write-Host 'PIN injection test. A hidden helper process will ask Windows to sign. After a short wait, this script will type a PIN into the prompt as synthetic keystrokes, with no human typing.' -ForegroundColor Yellow
    Write-Host 'You type your PIN here once, hidden. It stays in memory, is sent only as keystrokes to the Windows prompt on this PC, is never written to disk or the report, then is wiped.' -ForegroundColor Yellow
    Write-Host 'While the countdown runs: when the prompt appears, switch it to the PIN box (More choices / Sign-in options / PIN icon) if it shows fingerprint or face. Then take your hands off the keyboard and mouse.' -ForegroundColor Yellow
    $go = Ask 'Run the PIN injection test? (y = yes, s = skip)' @('y', 's')
    if ($go -eq 's') { return @{ result = 'skipped'; evidence = @{ reason = 'Skipped by the user.' } } }
    $sec = Read-Host 'PIN (hidden)' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    $chars = $null
    $ev = [ordered]@{}
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $chars = $plain.ToCharArray()
        $plain = $null
        $ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = $ps51
        $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -ChildSign "' + $script:Main.Name + '" -ChildProvider "' + $script:Main.Provider + '"'
        $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        $p = [Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        $wait = 12
        for ($i = $wait; $i -gt 0; $i--) { Write-Host ("  typing in " + $i + " s ...") -NoNewline; Start-Sleep -Seconds 1; Write-Host "`r" -NoNewline }
        Write-Host ''
        $sent = 0
        foreach ($c in $chars) {
            $sent += [HsUtil]::SendKey(0, [uint16]$c, 4)
            $sent += [HsUtil]::SendKey(0, [uint16]$c, 6)
            Start-Sleep -Milliseconds 80
        }
        $sent += [HsUtil]::SendKey(0x0D, 0, 0)
        $sent += [HsUtil]::SendKey(0x0D, 0, 2)
        $ev.keystroke_events_accepted_by_sendinput = $sent
        $ev.pin_length_typed = $chars.Length
        $done = $p.WaitForExit(30000)
        $ev.child_exited = $done
        if ($done) {
            $out = $p.StandardOutput.ReadToEnd().Trim()
            try { $ev.child_result = ($out | ConvertFrom-Json) } catch { $ev.child_stdout = $out }
        }
        else { try { $p.Kill() } catch { } }
    }
    finally {
        if ($chars) { [Array]::Clear($chars, 0, $chars.Length) }
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $sec.Dispose()
    }
    $ev.human_pin_box_was_visible = Ask 'Was the PIN box showing when the script typed? (y / n)' @('y', 'n')
    $ev.human_touched_keyboard = Ask 'Did you type or click anything after the countdown started? (y / n)' @('y', 'n')
    $signed = ($ev.child_result -and $ev.child_result.hr -eq '0x00000000' -and $ev.child_result.sigLen -gt 0)
    $ev.wsl_interop_variant = 'not testable from PowerShell'
    if ($ev.human_pin_box_was_visible -eq 'n' -or $ev.human_touched_keyboard -eq 'y') {
        return @{ result = 'skipped'; evidence = $ev; note = 'Inconclusive: the PIN box was not showing, or a human touched the input. Run again and keep hands off.' }
    }
    return @{ result = $(if ($signed) { 'yes' } else { 'no' }); evidence = $ev; note = 'yes means a process with no human at the keyboard completed a signature by injecting the PIN. That is the risk the biometric-only class exists to avoid.' }
}

function Step-S11 {
    Initialize-Agree
    $ev = [ordered]@{ attempts = @() }
    $sw = 'Microsoft Software Key Storage Provider'
    $info = [Text.Encoding]::ASCII.GetBytes('handsal-spike-agree-info')
    $attempts = @(
        @{ id = 'A_tpm_platform_crypto_no_hello'; prov = $script:ProvPcp; name = ('handsal-spike-agree-pcp-' + $script:Rand) },
        @{ id = 'B_passport_provider_no_hello'; prov = $script:ProvNgc; name = ('handsal-spike-agree-ngc-' + $script:Rand) },
        @{ id = 'C_software_control'; prov = $sw; name = ('handsal-spike-agree-sw-' + $script:Rand) }
    )
    $worked = @{}
    foreach ($a in $attempts) {
        Write-Host ("Trying " + $a.id + " (normally no window appears; if one does, approve it and say so at the end of this step)") -ForegroundColor DarkGray
        $k = New-Object HsAgree
        $hr = $k.Create($a.prov, $a.name)
        $rec = [ordered]@{ id = $a.id; provider = $a.prov; create_hr = [HsAgree]::Hex($hr); log = @($k.Log) }
        if ($hr -eq 0) {
            Register-Key $a.prov $a.name
            $impl = $k.GetDword('Impl Type')
            $rec.impl_type = $impl
            $rec.hardware = ($impl -ge 0 -and (($impl -band 1) -eq 1))
            $rec.algorithm = $k.GetStr('Algorithm Name')
            $rec.length_bits = $k.GetDword('Length')
            $rec.ui_policy_property = $k.Probe('UI Policy')
            $mine = $k.ExportPublic()
            # the other party holds a software key, as a sender on another machine would
            $peer = New-Object HsAgree
            $phr = $peer.Create($sw, $null)
            $rec.peer_create_hr = [HsAgree]::Hex($phr)
            $theirs = $null
            if ($phr -eq 0) { $theirs = $peer.ExportPublic() }
            if ($null -ne $mine -and $null -ne $theirs) {
                $rec.agreements = @()
                foreach ($kdf in @('HKDF', 'HASH')) {
                    foreach ($imp in @($a.prov, $sw)) {
                        $silent = [ordered]@{ kdf = $kdf; import_provider = $imp }
                        $sd = [Diagnostics.Stopwatch]::StartNew()
                        $hr1 = $k.AgreeAndDerive($theirs, $imp, $kdf, $info, 0x40)
                        $sd.Stop()
                        $silent.silent_call_hr = [HsAgree]::Hex($hr1)
                        $silent.silent_call_ms = $sd.ElapsedMilliseconds
                        $silent.log = @($k.Log | Select-Object -Last 4)
                        if ($hr1 -eq 0) {
                            $mineKey = $k.LastDerived
                            $hr2 = $peer.AgreeAndDerive($mine, $sw, $kdf, $info, 0)
                            $silent.peer_side_hr = [HsAgree]::Hex($hr2)
                            $silent.derived_length = $mineKey.Length
                            $silent.both_sides_equal = ($hr2 -eq 0 -and (ToHex $mineKey) -eq (ToHex $peer.LastDerived))
                            if ($silent.both_sides_equal -and -not $worked.ContainsKey($a.id)) { $worked[$a.id] = $kdf + ' via ' + $imp }
                        }
                        $rec.agreements += $silent
                    }
                }
            }
            $peer.Close()
        }
        $k.Close()
        $ev.attempts += $rec
    }
    $ev.agreement_worked = $worked
    $ev.human_window_seen = Ask 'Did ANY window appear during this step (Windows Hello, PIN, or anything else)? (y / n)' @('y', 'n')
    $tpm = @($ev.attempts | Where-Object { $_.id -like 'A_*' }) | Select-Object -First 1
    $tpmOk = ($worked.ContainsKey('A_tpm_platform_crypto_no_hello') -and $tpm.hardware -eq $true)
    $res = 'no'
    if ($tpmOk -and $ev.human_window_seen -eq 'n') { $res = 'yes' }
    $hkdf = 'no'
    if ($worked.ContainsKey('A_tpm_platform_crypto_no_hello') -and $worked['A_tpm_platform_crypto_no_hello'] -like 'HKDF*') { $hkdf = 'yes' }
    $ev.hkdf_done_by_the_platform = $hkdf
    return @{ result = $res; evidence = $ev; note = 'yes means a TPM key made with no Hello gating agreed with a peer key, silently, with no window. hkdf_done_by_the_platform says whether Windows could also run the HKDF step.' }
}

function Step-Clean {
    $ev = [ordered]@{ keys = @() }
    if ($script:Main) { $script:Main.Close() }
    foreach ($c in $script:Created) {
        $rec = [ordered]@{ kind = $c.kind; provider = $c.provider; name = (Redact $c.name) }
        try {
            if ($c.kind -eq 'ncrypt') {
                $k = New-Object HsKey
                $hr = $k.Open($c.provider, $c.name)
                if ($hr -eq 0) { $dh = $k.Delete(); $rec.delete_hr = [HsKey]::Hex($dh) } else { $rec.open_hr = [HsKey]::Hex($hr); $k.Close() }
                $v = New-Object HsKey
                $vh = $v.Open($c.provider, $c.name)
                $rec.reopen_after_delete_hr = [HsKey]::Hex($vh)
                $rec.gone = ($vh -ne 0)
                $v.Close()
            }
            elseif ($c.kind -eq 'winrt' -and $script:WinRt) {
                Wait-Act ([Windows.Security.Credentials.KeyCredentialManager]::DeleteAsync($c.name))
                $r = Wait-Op ([Windows.Security.Credentials.KeyCredentialManager]::OpenAsync($c.name)) ([Windows.Security.Credentials.KeyCredentialRetrievalResult])
                $rec.reopen_status = [string]$r.Status
                $rec.gone = ([string]$r.Status -ne 'Success')
            }
        }
        catch { $rec.error = $_.Exception.Message; $rec.gone = $false }
        $ev.keys += $rec
    }
    $ev.scratch_dirs = @()
    foreach ($d in $script:ScratchDirs) {
        try { Remove-Item -Path $d -Recurse -Force -ErrorAction Stop; $ev.scratch_dirs += @{ path = $d; removed = $true } }
        catch { $ev.scratch_dirs += @{ path = $d; removed = $false; error = $_.Exception.Message } }
    }
    $left = @($ev.keys | Where-Object { $_.gone -ne $true }).Count + @($ev.scratch_dirs | Where-Object { $_.removed -ne $true }).Count
    $ev.leftover = $left
    return @{ result = $(if ($left -eq 0) { 'yes' } else { 'no' }); evidence = $ev; note = 'yes means every key and folder this spike made is gone.' }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host 'handsal Windows Hello spike' -ForegroundColor Cyan
Write-Host 'This creates a few test keys on this PC, asks you to approve some Windows Hello prompts,'
Write-Host 'and deletes the keys at the end. Nothing is sent anywhere. The result is one JSON file'
Write-Host ('in this folder: ' + $script:ReportPath)
Write-Host ('Spike version ' + $script:SpikeVersion + ', script SHA-256: ' + $script:ScriptSha256)
Write-Host 'Compare that hash with the one published for this version before you go on.'
Write-Host 'It does not record your name, computer name, or PIN.'
Write-Host ''
if (-not [Environment]::UserInteractive) { Write-Host 'This spike needs a person at the keyboard.'; exit 3 }
[void](Read-Host 'Press Enter to start (Ctrl+C to quit)')

Initialize-WinRt

function Write-Report {
    $g = @{}
    foreach ($id in @('S1', 'S2', 'S3', 'S4', 'S8')) { $g[$id] = Get-StepResult $id }
    $gatePass = (@($g.Values | Where-Object { $_ -ne 'yes' }).Count -eq 0)
    $s10 = Get-StepResult 'S10'
    $uv = 'undetermined'
    if ($s10 -eq 'yes') { $uv = 'biometric_only' } elseif ($s10 -eq 'no') { $uv = 'biometric_or_pin' }
    $summary = [ordered]@{
        gating_steps_S1_S2_S3_S4_S8 = $g
        gating_all_pass = $gatePass
        s10_biometric_only_enforceable_by_app = $s10
        suggested_user_verification_for_win_hello_hw = $uv
        s10b_pin_injection_without_human = (Get-StepResult 'S10b')
        s11_agreement_key_without_hello_gating = (Get-StepResult 'S11')
        cleanup_complete = (Get-StepResult 'CLEAN')
    }
    $report = [ordered]@{
        spike = 'handsal-windows-hello'
        version = $script:SpikeVersion
        script_sha256 = $script:ScriptSha256
        started_utc = $script:Started
        finished_utc = (Get-Date).ToUniversalTime().ToString('o')
        powershell = $PSVersionTable.PSVersion.ToString()
        elevated = $script:Elevated
        summary = $summary
        steps = @($script:Steps)
    }
    # ConvertTo-Json runs only over data proven plain. Run-Step proved each step; this covers the rest.
    $bad = Find-NonPlainData $report 'report' 11
    if ($null -ne $bad) {
        Write-Host ('The report is not plain data, so only an error record is written: ' + $bad) -ForegroundColor Red
        $report = [ordered]@{
            spike = 'handsal-windows-hello'
            version = $script:SpikeVersion
            script_sha256 = $script:ScriptSha256
            report_refused = $bad
        }
    }
    $json = $report | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($script:ReportPath, $json, (New-Object Text.UTF8Encoding $false))

    Write-Host ''
    Write-Host '================ SUMMARY ================' -ForegroundColor Cyan
    foreach ($s in $script:Steps) { Write-Host ("{0,-6} {1,-8} {2}" -f $s.step, $s.result, $s.assumption) }
    Write-Host ''
    Write-Host ("Spike version {0}, script SHA-256: {1}" -f $script:SpikeVersion, $script:ScriptSha256)
    Write-Host ("Gating steps (S1 S2 S3 S4 S8) all pass: " + $gatePass)
    Write-Host ("S10 app can demand biometrics and refuse the PIN: " + $s10)
    Write-Host ("Suggested user_verification for win-hello-hw: " + $uv)
    Write-Host ("S11 a TPM key without Hello gating can do a key agreement: " + (Get-StepResult 'S11'))
    Write-Host ("Keys and folders removed: " + (Get-StepResult 'CLEAN'))
    Write-Host ''
    Write-Host ("Report written to: " + $script:ReportPath) -ForegroundColor Green
    Write-Host 'Please send that file back. It contains no name, computer name, or PIN.'
}

try {
    Run-Step 'S0' 'This machine has a TPM, Windows Hello is set up, and the hardware key providers can be opened' { Step-S0 }
    Run-Step 'S1' 'A P-256 ECDSA key can be created in a hardware provider (Passport KSP or TPM)' { Step-S1 }
    Run-Step 'S2' 'That key cannot be exported' { Step-S2 }
    Run-Step 'S3' 'Signing prompts the user and returns a raw 64-byte R||S that verifies; high-S is detected and normalized' { Step-S3 }
    Run-Step 'S4' 'Every signature needs a fresh user verification and a silent call fails' { Step-S4 }
    Run-Step 'S5' 'The default Hello prompt offers a PIN path; key properties that could restrict it are listed' { Step-S5 }
    Run-Step 'S6' 'The key survives an enrollment change (optional)' { Step-S6 }
    Run-Step 'S7' 'Cancelling the prompt gives no signature and a distinct error' { Step-S7 }
    Run-Step 'S8' 'A piped, windowless process gets a visible prompt and a signature (WSL2-style call); WSL root access recorded' { Step-S8 }
    Run-Step 'S9' 'C:\ProgramData can hold a folder with an admin-only-write DACL that standard users cannot change' { Step-S9 }
    Run-Step 'S10' 'An app can demand biometric verification and refuse PIN fallback at the API level' { Step-S10 }
    Run-Step 'S10b' 'A same-user process with no human can satisfy the PIN prompt by injecting keystrokes (record only)' { Step-S10b }
    Run-Step 'S11' 'A TPM key made without Windows Hello gating can do an ECDH key agreement with a peer key, silently' { Step-S11 }
}
finally {
    Run-Step 'CLEAN' 'Every key and folder the spike created is deleted' { Step-Clean }
    Write-Report
}
