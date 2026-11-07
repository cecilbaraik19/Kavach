using System.Diagnostics;
using Microsoft.Win32;

namespace Kavach.Core.Infrastructure;

/// <summary>Right-click "Scan with Kavach" menu, start with Windows, and restart as administrator.</summary>
public static class WindowsIntegration
{
    private const string MenuKeyName = "KavachScan";
    private const string RunValueName = "Kavach";

    public static string AppExePath => Environment.ProcessPath ?? Path.Combine(AppPaths.AppDir, "Kavach.exe");

    /// <summary>Adds "Scan with Kavach" for files, folders and drives (current user, no admin needed).</summary>
    public static void RegisterContextMenu()
    {
        var exe = AppExePath;
        foreach (var root in new[] { @"Software\Classes\*\shell", @"Software\Classes\Directory\shell", @"Software\Classes\Drive\shell" })
        {
            using var key = Registry.CurrentUser.CreateSubKey($@"{root}\{MenuKeyName}");
            key.SetValue("", "Scan with Kavach");
            key.SetValue("Icon", $"\"{exe}\",0");
            using var command = key.CreateSubKey("command");
            command.SetValue("", $"\"{exe}\" --scan \"%1\"");
        }
    }

    public static void UnregisterContextMenu()
    {
        foreach (var root in new[] { @"Software\Classes\*\shell", @"Software\Classes\Directory\shell", @"Software\Classes\Drive\shell" })
        {
            try { Registry.CurrentUser.DeleteSubKeyTree($@"{root}\{MenuKeyName}", throwOnMissingSubKey: false); } catch { }
        }
    }

    public static void SetStartWithWindows(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
        if (enabled) key.SetValue(RunValueName, $"\"{AppExePath}\" --tray");
        else key.DeleteValue(RunValueName, throwOnMissingValue: false);
    }

    /// <summary>Starts a new copy of Kavach as administrator (shows the Windows UAC prompt).</summary>
    public static bool RestartAsAdmin(string arguments = "")
    {
        try
        {
            Process.Start(new ProcessStartInfo(AppExePath, arguments + " --elevated")
            {
                UseShellExecute = true,
                Verb = "runas"
            });
            return true;
        }
        catch
        {
            return false; // user clicked "No"
        }
    }

    public static void OpenInExplorer(string path)
    {
        try
        {
            if (File.Exists(path)) Process.Start("explorer.exe", $"/select,\"{path}\"");
            else if (Directory.Exists(path)) Process.Start("explorer.exe", $"\"{path}\"");
            else
            {
                var dir = Path.GetDirectoryName(path);
                if (dir != null && Directory.Exists(dir)) Process.Start("explorer.exe", $"\"{dir}\"");
            }
        }
        catch
        {
        }
    }

    public static void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
    }
}
