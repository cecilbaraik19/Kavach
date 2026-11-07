using System.Diagnostics;
using Kavach.Core.Infrastructure;
using Kavach.Core.Native;

namespace Kavach.Core.Protection;

/// <summary>
/// Self-protection (tamper protection). Malware often tries to close the antivirus first.
///  • Changes the security of Kavach's own process so normal programs cannot terminate it,
///    write into its memory or inject code. Only SYSTEM keeps full access.
///  • The Windows Service is set (by the installer) to restart automatically if it is stopped.
/// Note: a program already running as Administrator with debug rights can still get past this;
/// only kernel-level drivers (like commercial antivirus) can fully stop that.
/// </summary>
public static class SelfProtection
{
    // D:P = protected DACL (not inherited)
    // SYSTEM: full access. Everyone/Admins: only query, read and synchronize (no terminate, no memory write, no inject).
    private const string ProtectedProcessSddl =
        "D:P(A;;GA;;;SY)(A;;0x101000;;;BA)(A;;0x101000;;;WD)(A;;0x101000;;;OW)";

    public static bool IsApplied { get; private set; }

    public static bool Apply(ActivityLog? log = null)
    {
        IntPtr descriptor = IntPtr.Zero;
        try
        {
            if (!NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(ProtectedProcessSddl, 1, out descriptor, out _))
                return false;
            if (!NativeMethods.GetSecurityDescriptorDacl(descriptor, out var present, out var dacl, out _) || !present)
                return false;

            var result = NativeMethods.SetSecurityInfo(NativeMethods.GetCurrentProcess(), NativeMethods.SE_KERNEL_OBJECT,
                NativeMethods.DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);

            IsApplied = result == 0;
            if (IsApplied) log?.Info("Self-protection", $"Process protection applied to {Process.GetCurrentProcess().ProcessName}");
            else log?.Warning("Self-protection", $"Could not protect the process (error {result})");
            return IsApplied;
        }
        catch (Exception ex)
        {
            log?.Warning("Self-protection", ex.Message);
            return false;
        }
        finally
        {
            if (descriptor != IntPtr.Zero) NativeMethods.LocalFree(descriptor);
        }
    }
}
