namespace Kavach.Core.Engine;

/// <summary>
/// Checks that only need the file name and folder (no reading of the content):
/// file types, double extensions, fake Windows system files and look-alike names.
/// </summary>
public static class FileClassifier
{
    public static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".ocx", ".drv", ".efi", ".msp", ".appx", ".msix"
    };

    public static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".reg", ".url", ".scf"
    };

    public static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".jar", ".apk", ".bz2", ".xz"
    };

    public static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx", ".pdf", ".rtf", ".one", ".iso", ".img", ".vhd", ".chm", ".html", ".htm", ".svg", ".php", ".py", ".txt"
    };

    /// <summary>Big media files that are almost never a threat. Skipped when "Skip media files" is on.</summary>
    public static readonly HashSet<string> MediaExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".raw", ".psd", ".ttf", ".otf", ".woff", ".woff2",
        ".vmdk", ".vdi", ".pst", ".ost", ".mdf", ".ldf", ".pak", ".bundle", ".blend"
    };

    /// <summary>
    /// File types a user would double-click to open. Only these are checked for the double-extension trick
    /// (system names like Windows.Data.Pdf.dll and Office shortcuts like Report.docx.url are normal).
    /// </summary>
    private static readonly HashSet<string> DoubleExtensionTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".msi", ".cpl"
    };

    public static bool IsInWindowsFolder(string path)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return windows.Length > 0
               && path.StartsWith(windows.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)
               && !path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Library folders made by programming tools (npm, pip, composer …). Files there such as
    /// "es.iterator.zip.js" are normal source code that nobody double-clicks, so the
    /// double-extension NAME check is skipped there (the file contents are still scanned).
    /// </summary>
    private static readonly string[] DeveloperPackageFolders =
    {
        @"\node_modules\", @"\site-packages\", @"\dist-packages\", @"\vendor\", @"\bower_components\", @"\.git\"
    };

    public static bool IsInDeveloperPackageFolder(string path) =>
        DeveloperPackageFolders.Any(f => path.Contains(f, StringComparison.OrdinalIgnoreCase));

    /// <summary>Files that look like documents/pictures. Used for the double extension check.</summary>
    private static readonly HashSet<string> DecoyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif",
        ".bmp", ".mp3", ".mp4", ".avi", ".mkv", ".zip", ".rar", ".csv", ".odt", ".html"
    };

    /// <summary>Windows system programs and the only folders they should run from.</summary>
    private static readonly Dictionary<string, string[]> SystemFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost.exe"] = new[] { "System32", "SysWOW64" },
        ["lsass.exe"] = new[] { "System32" },
        ["csrss.exe"] = new[] { "System32" },
        ["smss.exe"] = new[] { "System32" },
        ["wininit.exe"] = new[] { "System32" },
        ["winlogon.exe"] = new[] { "System32" },
        ["services.exe"] = new[] { "System32" },
        ["spoolsv.exe"] = new[] { "System32" },
        ["explorer.exe"] = new[] { "", "System32", "SysWOW64" },
        ["dllhost.exe"] = new[] { "System32", "SysWOW64" },
        ["rundll32.exe"] = new[] { "System32", "SysWOW64" },
        ["taskhostw.exe"] = new[] { "System32" },
        ["conhost.exe"] = new[] { "System32" },
        ["dwm.exe"] = new[] { "System32" },
        ["taskmgr.exe"] = new[] { "System32", "SysWOW64" },
        ["ctfmon.exe"] = new[] { "System32", "SysWOW64" },
        ["sihost.exe"] = new[] { "System32" },
        ["lsm.exe"] = new[] { "System32" },
        ["regsvr32.exe"] = new[] { "System32", "SysWOW64" },
        ["wmiprvse.exe"] = new[] { "System32\\wbem", "SysWOW64\\wbem" }
    };

    /// <summary>Misspelled copies of system names that malware often uses.</summary>
    private static readonly HashSet<string> LookalikeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "scvhost.exe", "svch0st.exe", "svhost.exe", "svchosts.exe", "svchost32.exe", "scvh0st.exe", "lsas.exe", "lsasss.exe",
        "1sass.exe", "csrrs.exe", "cssrs.exe", "expl0rer.exe", "explore.exe", "iexplorer.exe", "winlog0n.exe", "smms.exe",
        "spoolsvc.exe", "taskhost32.exe", "rundll.exe", "rundl32.exe", "dllhst.exe", "ctfmom.exe", "conhosts.exe", "wininit32.exe"
    };

    public static bool IsExecutable(string path) => ExecutableExtensions.Contains(Path.GetExtension(path));
    public static bool IsScript(string path) => ScriptExtensions.Contains(Path.GetExtension(path));
    public static bool IsArchive(string path) => ArchiveExtensions.Contains(Path.GetExtension(path));
    public static bool IsMedia(string path) => MediaExtensions.Contains(Path.GetExtension(path));

    /// <summary>Should Quick/Full scan open this file? (Custom scan opens every file.)</summary>
    public static bool IsInteresting(string path)
    {
        var ext = Path.GetExtension(path);
        return ext.Length == 0
               || ExecutableExtensions.Contains(ext)
               || ScriptExtensions.Contains(ext)
               || ArchiveExtensions.Contains(ext)
               || DocumentExtensions.Contains(ext);
    }

    /// <summary>All name-based checks for one file.</summary>
    public static IEnumerable<Detection> CheckName(string path)
    {
        var fileName = Path.GetFileName(path);

        // Right-to-left override character hides the real extension: "invoice\u202Efdp.exe" shows as "invoiceexe.pdf"
        if (fileName.Contains('\u202E'))
        {
            yield return new Detection
            {
                FilePath = path,
                ThreatName = "Suspicious.HiddenExtension.RTLO",
                Level = ThreatLevel.High,
                Source = DetectionSource.FileName,
                Details = "File name uses a hidden right-to-left character to fake its extension"
            };
        }

        var ext = Path.GetExtension(fileName);
        if (DoubleExtensionTargets.Contains(ext) && !IsInWindowsFolder(path) && !IsInDeveloperPackageFolder(path))
        {
            var withoutLast = fileName[..^ext.Length];
            var trimmed = withoutLast.TrimEnd(' ', '.', '_');
            var innerExt = Path.GetExtension(trimmed);
            if (innerExt.Length > 0 && DecoyExtensions.Contains(innerExt) && !ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
            {
                var padded = withoutLast.Length - trimmed.Length >= 3;
                yield return new Detection
                {
                    FilePath = path,
                    ThreatName = "Suspicious.DoubleExtension",
                    Level = ThreatLevel.High,
                    Source = DetectionSource.FileName,
                    Details = padded
                        ? $"Looks like a {innerExt} file but is really a {ext} program (extra spaces hide the real extension)"
                        : $"Looks like a {innerExt} file but is really a {ext} program"
                };
            }
        }

        if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            if (SystemFiles.TryGetValue(fileName, out var allowedDirs) && !IsInAllowedSystemFolder(path, allowedDirs))
            {
                yield return new Detection
                {
                    FilePath = path,
                    ThreatName = "Suspicious.Fake" + CultureCap(Path.GetFileNameWithoutExtension(fileName)),
                    Level = ThreatLevel.Critical,
                    Source = DetectionSource.FakeSystemFile,
                    Details = $"{fileName} is a Windows system file but this copy is outside the Windows folder"
                };
            }
            else if (LookalikeNames.Contains(fileName))
            {
                yield return new Detection
                {
                    FilePath = path,
                    ThreatName = "Suspicious.LookalikeSystemName",
                    Level = ThreatLevel.High,
                    Source = DetectionSource.FakeSystemFile,
                    Details = $"{fileName} is a misspelled copy of a Windows system file name"
                };
            }
        }
    }

    private static string CultureCap(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..].ToLowerInvariant();

    private static bool IsInAllowedSystemFolder(string path, string[] allowedDirs)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(windows)) windows = @"C:\Windows";

        var dir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? "";

        // Windows keeps backup copies of system files in WinSxS, servicing and update folders
        foreach (var store in new[] { "WinSxS", "servicing", "SoftwareDistribution", "Prefetch" })
        {
            if (dir.StartsWith(Path.Combine(windows, store), StringComparison.OrdinalIgnoreCase)) return true;
        }

        foreach (var allowed in allowedDirs)
        {
            var expected = allowed.Length == 0 ? windows : Path.Combine(windows, allowed);
            if (string.Equals(dir.TrimEnd('\\'), expected.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true;
        }

        // Files on other drives or mounted Windows images (e.g. D:\Windows\System32) are also normal
        var root = Path.GetPathRoot(dir) ?? "";
        foreach (var allowed in allowedDirs)
        {
            var other = allowed.Length == 0 ? Path.Combine(root, "Windows") : Path.Combine(root, "Windows", allowed);
            if (string.Equals(dir.TrimEnd('\\'), other.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>Folders where trusted, installed software lives.</summary>
    public static bool IsInTrustedInstallFolder(string path)
    {
        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
        };
        foreach (var f in folders)
        {
            if (string.IsNullOrEmpty(f)) continue;
            if (path.StartsWith(f.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
            {
                // ...except the writable temp folder inside Windows
                if (path.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase)) return false;
                return true;
            }
        }
        return false;
    }

    /// <summary>Folders malware likes to run from.</summary>
    public static bool IsInUserWritableFolder(string path)
    {
        var temp = Path.GetTempPath();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var publicDir = Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public";
        return path.StartsWith(temp, StringComparison.OrdinalIgnoreCase)
               || path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase)
               || path.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase)
               || (roaming.Length > 0 && path.StartsWith(roaming, StringComparison.OrdinalIgnoreCase))
               || (local.Length > 0 && path.StartsWith(local, StringComparison.OrdinalIgnoreCase))
               || path.StartsWith(publicDir, StringComparison.OrdinalIgnoreCase)
               || path.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) && !path.Contains(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
    }
}
