namespace Kavach.Core.Scanning;

/// <summary>A folder to scan and how deep to go (-1 = all sub-folders).</summary>
public sealed record ScanTarget(string Path, int MaxDepth = -1);

/// <summary>Which folders each scan type covers.</summary>
public static class ScanLocations
{
    /// <summary>Places where malware usually lands or hides.</summary>
    public static List<ScanTarget> Quick()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var targets = new List<ScanTarget>
        {
            new(Path.Combine(profile, "Downloads"), 3),
            new(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), 2),
            new(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), 2),
            new(Path.GetTempPath(), 3),
            new(Environment.GetFolderPath(Environment.SpecialFolder.Startup), 1),
            new(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), 1),
            new(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 3),
            new(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 2),
            new(Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public", 3),
            new(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 2),
            new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"), 2)
        };
        return targets.Where(t => !string.IsNullOrWhiteSpace(t.Path) && Directory.Exists(t.Path))
                      .GroupBy(t => t.Path.TrimEnd('\\'), StringComparer.OrdinalIgnoreCase)
                      .Select(g => g.OrderByDescending(t => t.MaxDepth).First())
                      .ToList();
    }

    /// <summary>Every fixed drive.</summary>
    public static List<ScanTarget> Full()
    {
        return DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => new ScanTarget(d.RootDirectory.FullName))
            .ToList();
    }

    /// <summary>Folders skipped during Full scan because they are huge and only hold Windows' own signed files.</summary>
    public static bool IsSkippedFolder(string folder)
    {
        var name = System.IO.Path.GetFileName(folder.TrimEnd('\\'));
        if (name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Equals("$WinREAgent", StringComparison.OrdinalIgnoreCase)) return true;

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (windows.Length == 0) return false;
        return folder.Equals(System.IO.Path.Combine(windows, "WinSxS"), StringComparison.OrdinalIgnoreCase)
               || folder.Equals(System.IO.Path.Combine(windows, "servicing"), StringComparison.OrdinalIgnoreCase)
               || folder.Equals(System.IO.Path.Combine(windows, "Installer"), StringComparison.OrdinalIgnoreCase)
               || folder.Equals(System.IO.Path.Combine(windows, "assembly"), StringComparison.OrdinalIgnoreCase);
    }
}
