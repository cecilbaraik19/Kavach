using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Kavach.Core.Native;

namespace Kavach.Core.Engine;

public enum SignatureStatus
{
    Unknown,
    Valid,
    Invalid,
    Unsigned
}

public sealed record SignatureInfo(SignatureStatus Status, string? Signer)
{
    public bool IsTrusted => Status == SignatureStatus.Valid;

    public string Describe() => Status switch
    {
        SignatureStatus.Valid => $"Signed by {Signer ?? "a trusted publisher"}",
        SignatureStatus.Invalid => "Signature is invalid or tampered",
        SignatureStatus.Unsigned => "Not digitally signed",
        _ => "Signature unknown"
    };
}

/// <summary>
/// Checks the Authenticode digital signature of a program using Windows' own WinVerifyTrust.
/// A valid signature means the publisher is known and the file was not changed after signing.
/// </summary>
public static class SignatureVerifier
{
    private static readonly ConcurrentDictionary<string, (DateTime Stamp, SignatureInfo Info)> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static SignatureInfo Check(string path)
    {
        try
        {
            var stamp = File.GetLastWriteTimeUtc(path);
            if (Cache.TryGetValue(path, out var cached) && cached.Stamp == stamp) return cached.Info;

            var status = Verify(path);
            string? signer = null;
            if (status != SignatureStatus.Unsigned)
            {
                try
                {
#pragma warning disable SYSLIB0057
                    using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
                    signer = cert.GetNameInfo(X509NameType.SimpleName, false);
                }
                catch
                {
                    // no readable certificate
                }
            }

            var info = new SignatureInfo(status, signer);
            if (Cache.Count > 20_000) Cache.Clear();
            Cache[path] = (stamp, info);
            return info;
        }
        catch
        {
            return new SignatureInfo(SignatureStatus.Unknown, null);
        }
    }

    private static SignatureStatus Verify(string path)
    {
        var fileInfo = new NativeMethods.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>());
        var dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WINTRUST_DATA>());
        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            var data = new NativeMethods.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_DATA>(),
                dwUIChoice = NativeMethods.WTD_UI_NONE,
                fdwRevocationChecks = NativeMethods.WTD_REVOKE_NONE,
                dwUnionChoice = NativeMethods.WTD_CHOICE_FILE,
                pFile = filePtr,
                dwStateAction = NativeMethods.WTD_STATEACTION_VERIFY,
                dwProvFlags = NativeMethods.WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            Marshal.StructureToPtr(data, dataPtr, false);

            var result = NativeMethods.WinVerifyTrust(IntPtr.Zero, NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, dataPtr);

            // Release the state Windows kept for us
            data = Marshal.PtrToStructure<NativeMethods.WINTRUST_DATA>(dataPtr);
            data.dwStateAction = NativeMethods.WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, dataPtr, true);
            NativeMethods.WinVerifyTrust(IntPtr.Zero, NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, dataPtr);

            const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
            const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
            const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);

            return result switch
            {
                0 => SignatureStatus.Valid,
                TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN => SignatureStatus.Unsigned,
                _ => SignatureStatus.Invalid
            };
        }
        finally
        {
            Marshal.DestroyStructure<NativeMethods.WINTRUST_FILE_INFO>(filePtr);
            Marshal.FreeHGlobal(filePtr);
            Marshal.FreeHGlobal(dataPtr);
        }
    }
}
