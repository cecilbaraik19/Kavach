using System.Security.AccessControl;
using System.Security.Principal;

namespace Kavach.Core.Infrastructure;

/// <summary>
/// All folders and files Kavach uses.
/// Data lives in C:\ProgramData\Kavach so the app and the Windows Service share it.
/// </summary>
public static class AppPaths
{
    public const string ProductName = "Kavach";
    public const string Publisher = "Cecil Baraik";
    /// <summary>Version number from Directory.Build.props (for example "1.1.0").</summary>
    public static string Version { get; } =
        typeof(AppPaths).Assembly.GetName().Version is { } v ? v.ToString(3) : "1.0.0";

    public static string DataDir { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), ProductName);

    public static string QuarantineDir => Path.Combine(DataDir, "Quarantine");
    public static string SignaturesDir => Path.Combine(DataDir, "Signatures");
    public static string RulesDir => Path.Combine(SignaturesDir, "rules");
    public static string BackupDir => Path.Combine(DataDir, "Backups");
    public static string ReportsDir => Path.Combine(DataDir, "Reports");

    public static string SettingsFile => Path.Combine(DataDir, "settings.json");
    public static string HistoryFile => Path.Combine(DataDir, "history.json");
    public static string QuarantineIndexFile => Path.Combine(QuarantineDir, "index.json");
    public static string ActivityLogFile => Path.Combine(DataDir, "activity.log");
    public static string ScanCacheFile => Path.Combine(DataDir, "scancache.json");
    public static string DisabledStartupFile => Path.Combine(BackupDir, "disabled-startup.json");

    /// <summary>Folder where the program itself is installed.</summary>
    public static string AppDir => AppContext.BaseDirectory;

    /// <summary>Default signatures shipped next to the program.</summary>
    public static string BundledSignaturesDir => Path.Combine(AppDir, "Signatures");

    /// <summary>Named pipe used by the Windows Service to send events to the app.</summary>
    public const string EventPipeName = "Kavach.Events";

    public static void EnsureDirectories()
    {
        foreach (var dir in new[] { DataDir, QuarantineDir, SignaturesDir, RulesDir, BackupDir, ReportsDir })
        {
            try { Directory.CreateDirectory(dir); } catch { /* not fatal */ }
        }

        TryGrantUsersModify();
        CopyBundledSignaturesIfMissing();
    }

    /// <summary>
    /// The service runs as SYSTEM and the app runs as the user, so normal users need write access
    /// to the data folder. This only works when running as administrator (installer / service).
    /// </summary>
    private static void TryGrantUsersModify()
    {
        if (!AdminHelper.IsAdministrator()) return;
        try
        {
            var dirInfo = new DirectoryInfo(DataDir);
            var security = dirInfo.GetAccessControl();
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                users,
                FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            dirInfo.SetAccessControl(security);
        }
        catch
        {
            // Not fatal: the installer also sets this permission.
        }
    }

    private static void CopyBundledSignaturesIfMissing()
    {
        try
        {
            if (!Directory.Exists(BundledSignaturesDir)) return;
            foreach (var source in Directory.EnumerateFiles(BundledSignaturesDir, "*", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(BundledSignaturesDir, source);
                var target = Path.Combine(SignaturesDir, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);

                // Always refresh the shipped files; user-imported files have different names.
                var copy = !File.Exists(target) || File.GetLastWriteTimeUtc(source) > File.GetLastWriteTimeUtc(target);
                if (copy) File.Copy(source, target, true);
            }
        }
        catch
        {
            // Signatures can still be imported from the Updates page.
        }
    }

    public static string UserFolder(Environment.SpecialFolder folder) => Environment.GetFolderPath(folder);

    public static string DownloadsFolder
    {
        get
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return Path.Combine(profile, "Downloads");
        }
    }

    /// <summary>True when the path is inside Kavach's own folders (never scan ourselves).</summary>
    public static bool IsOwnPath(string path)
    {
        return IsUnder(path, DataDir) || IsUnder(path, AppDir);
    }

    public static bool IsUnder(string path, string folder)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(folder)) return false;
        var full = NormalizeFolder(path);
        var root = NormalizeFolder(folder);
        return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeFolder(string p)
    {
        try { p = Path.GetFullPath(p); } catch { }
        return p.EndsWith('\\') ? p : p + "\\";
    }
}

public static class AdminHelper
{
    public static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static bool IsLocalSystem()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch
        {
            return false;
        }
    }
}
