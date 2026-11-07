using System.Diagnostics;
using System.Xml.Linq;
using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;
using Microsoft.Win32;

namespace Kavach.Core.SystemChecks;

public enum StartupSource
{
    RegistryRun,
    StartupFolder,
    ScheduledTask,
    Service,
    Winlogon,
    ImageHijack
}

/// <summary>Something that starts automatically with Windows.</summary>
public sealed class StartupItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public StartupSource Source { get; set; }
    /// <summary>Registry key, folder or task path.</summary>
    public string Location { get; set; } = "";
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public string? FilePath { get; set; }
    public bool FileExists { get; set; }
    public SignatureInfo? Signature { get; set; }
    public ThreatLevel Risk { get; set; }
    public string Reason { get; set; } = "Looks normal";
    public Detection? EngineDetection { get; set; }
    public bool CanDisable { get; set; } = true;

    public string SourceText => Source switch
    {
        StartupSource.RegistryRun => "Registry Run key",
        StartupSource.StartupFolder => "Startup folder",
        StartupSource.ScheduledTask => "Scheduled task",
        StartupSource.Service => "Windows service",
        StartupSource.Winlogon => "Winlogon",
        _ => "Program hijack (IFEO)"
    };

    public Detection? ToDetection()
    {
        if (Risk < ThreatLevel.Medium) return null;
        return new Detection
        {
            FilePath = FilePath ?? Command,
            ThreatName = EngineDetection?.ThreatName ?? (Source == StartupSource.Winlogon || Source == StartupSource.ImageHijack
                ? "Hijack." + Source
                : "Suspicious.StartupItem"),
            Level = Risk,
            Source = DetectionSource.Startup,
            Sha256 = EngineDetection?.Sha256,
            Details = $"{SourceText} \"{Name}\": {Reason}"
        };
    }
}

/// <summary>Backup of a startup item the user disabled, so it can be restored.</summary>
public sealed class DisabledStartupEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public StartupSource Source { get; set; }
    public string Name { get; set; } = "";
    public string Location { get; set; } = "";
    public string Command { get; set; } = "";
    /// <summary>For startup-folder items: where the file was moved.</summary>
    public string? BackupFile { get; set; }
    public DateTime DisabledAt { get; set; } = DateTime.Now;
}

/// <summary>
/// Finds everything that starts with Windows (Run keys, Startup folders, scheduled tasks, services,
/// Winlogon and IFEO hijacks) and scans the program behind each one.
/// </summary>
public static class StartupScanner
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceKey = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string RunKeyWow = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceKeyWow = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce";

    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
    };

    private static readonly string[] ScanableExtensions = { ".exe", ".dll", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".ps1", ".hta", ".scr", ".wsf", ".com", ".lnk" };

    public static List<StartupItem> Scan(ScanEngine engine, CancellationToken token)
    {
        var items = new List<StartupItem>();

        // Registry Run keys
        foreach (var (hive, hiveName) in UserHives())
        {
            ReadRunKey(items, hive, hiveName, RunKey);
            ReadRunKey(items, hive, hiveName, RunOnceKey);
        }
        ReadRunKey(items, Registry.LocalMachine, "HKLM", RunKey);
        ReadRunKey(items, Registry.LocalMachine, "HKLM", RunOnceKey);
        ReadRunKey(items, Registry.LocalMachine, "HKLM", RunKeyWow);
        ReadRunKey(items, Registry.LocalMachine, "HKLM", RunOnceKeyWow);

        // Startup folders
        ReadStartupFolder(items, Environment.GetFolderPath(Environment.SpecialFolder.Startup));
        ReadStartupFolder(items, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));

        token.ThrowIfCancellationRequested();
        ReadScheduledTasks(items);
        ReadServices(items);
        CheckWinlogon(items);
        CheckImageHijacks(items);

        foreach (var item in items)
        {
            token.ThrowIfCancellationRequested();
            Evaluate(item, engine, token);
        }
        return items;
    }

    // ───────────────────────── Readers ─────────────────────────

    /// <summary>The current user's registry; when running as the service (SYSTEM), every user's registry.</summary>
    private static IEnumerable<(RegistryKey Hive, string Name)> UserHives()
    {
        if (!AdminHelper.IsLocalSystem())
        {
            yield return (Registry.CurrentUser, "HKCU");
            yield break;
        }

        var sids = Array.Empty<string>();
        try { sids = Registry.Users.GetSubKeyNames(); }
        catch { /* no access */ }

        foreach (var sid in sids)
        {
            if (!sid.StartsWith("S-1-5-21-") || sid.EndsWith("_Classes")) continue;
            RegistryKey? key = null;
            try { key = Registry.Users.OpenSubKey(sid); } catch { }
            if (key != null) yield return (key, @"HKU\" + sid);
        }
    }

    private static void ReadRunKey(List<StartupItem> items, RegistryKey hive, string hiveName, string subKey)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey);
            if (key == null) return;
            foreach (var name in key.GetValueNames())
            {
                var command = key.GetValue(name)?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(command)) continue;
                items.Add(new StartupItem
                {
                    Source = StartupSource.RegistryRun,
                    Location = $@"{hiveName}\{subKey}",
                    Name = name.Length == 0 ? "(Default)" : name,
                    Command = command
                });
            }
        }
        catch
        {
            // no permission
        }
    }

    private static void ReadStartupFolder(List<StartupItem> items, string folder)
    {
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                if (Path.GetFileName(file).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                items.Add(new StartupItem
                {
                    Source = StartupSource.StartupFolder,
                    Location = folder,
                    Name = Path.GetFileName(file),
                    Command = file,
                    FilePath = file
                });
            }
        }
        catch
        {
        }
    }

    private static void ReadScheduledTasks(List<StartupItem> items)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
        if (!Directory.Exists(root)) return;

        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 };
        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(root, "*", options).ToList(); }
        catch { return; }

        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        foreach (var file in files)
        {
            try
            {
                var relative = "\\" + Path.GetRelativePath(root, file);
                var doc = XDocument.Load(file);
                var enabled = doc.Descendants(ns + "Settings").Elements(ns + "Enabled").FirstOrDefault()?.Value;
                if (string.Equals(enabled, "false", StringComparison.OrdinalIgnoreCase)) continue;

                foreach (var exec in doc.Descendants(ns + "Exec"))
                {
                    var command = exec.Element(ns + "Command")?.Value?.Trim() ?? "";
                    var args = exec.Element(ns + "Arguments")?.Value?.Trim() ?? "";
                    if (command.Length == 0) continue;
                    var full = command.StartsWith('"') || !command.Contains(' ') ? command + " " + args : $"\"{command}\" {args}";

                    var isMicrosoft = relative.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
                    if (isMicrosoft && !LooksUserWritable(Environment.ExpandEnvironmentVariables(command))) continue;

                    items.Add(new StartupItem
                    {
                        Source = StartupSource.ScheduledTask,
                        Location = relative,
                        Name = Path.GetFileName(relative),
                        Command = full.Trim()
                    });
                }
            }
            catch
            {
                // not a task file or no permission
            }
        }
    }

    private static void ReadServices(List<StartupItem> items)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services == null) return;
            foreach (var name in services.GetSubKeyNames())
            {
                try
                {
                    using var key = services.OpenSubKey(name);
                    if (key == null) continue;
                    var type = Convert.ToInt32(key.GetValue("Type") ?? 0);
                    var start = Convert.ToInt32(key.GetValue("Start") ?? 4);
                    if ((type & 0x30) == 0 || start > 2) continue; // only automatic Win32 services

                    var image = key.GetValue("ImagePath")?.ToString();
                    if (string.IsNullOrWhiteSpace(image)) continue;
                    var path = ExtractPath(image);
                    if (path != null && FileClassifier.IsInTrustedInstallFolder(path) && !LooksUserWritable(path)) continue;

                    var displayName = key.GetValue("DisplayName")?.ToString();
                    var niceName = !string.IsNullOrEmpty(displayName) && !displayName.StartsWith('@') ? displayName : name;
                    items.Add(new StartupItem
                    {
                        Source = StartupSource.Service,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\" + name,
                        Name = niceName,
                        Command = image,
                        CanDisable = false
                    });
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
    }

    private static void CheckWinlogon(List<StartupItem> items)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Winlogon");
            if (key == null) return;

            var shell = key.GetValue("Shell")?.ToString()?.Trim() ?? "explorer.exe";
            if (!shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                items.Add(new StartupItem
                {
                    Source = StartupSource.Winlogon,
                    Location = @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    Name = "Shell",
                    Command = shell,
                    Risk = ThreatLevel.High,
                    Reason = "The Windows shell was changed from explorer.exe",
                    CanDisable = false
                });
            }

            var userinit = key.GetValue("Userinit")?.ToString()?.Trim().TrimEnd(',') ?? "";
            if (userinit.Length > 0 && !userinit.EndsWith(@"\system32\userinit.exe", StringComparison.OrdinalIgnoreCase))
            {
                items.Add(new StartupItem
                {
                    Source = StartupSource.Winlogon,
                    Location = @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    Name = "Userinit",
                    Command = userinit,
                    Risk = ThreatLevel.High,
                    Reason = "Extra program added to the Windows logon (Userinit)",
                    CanDisable = false
                });
            }
        }
        catch
        {
        }
    }

    /// <summary>Image File Execution Options "Debugger" values make Windows run another program instead.
    /// Malware uses it to block antivirus tools or Task Manager.</summary>
    private static void CheckImageHijacks(List<StartupItem> items)
    {
        try
        {
            using var ifeo = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            if (ifeo == null) return;
            foreach (var exe in ifeo.GetSubKeyNames())
            {
                using var key = ifeo.OpenSubKey(exe);
                var debugger = key?.GetValue("Debugger")?.ToString();
                if (string.IsNullOrWhiteSpace(debugger)) continue;
                // vsjitdebugger is set by Visual Studio and is normal
                if (debugger.Contains("vsjitdebugger", StringComparison.OrdinalIgnoreCase)) continue;
                items.Add(new StartupItem
                {
                    Source = StartupSource.ImageHijack,
                    Location = @"HKLM\...\Image File Execution Options\" + exe,
                    Name = exe,
                    Command = debugger,
                    Risk = debugger.Contains("systray", StringComparison.OrdinalIgnoreCase) || debugger.Trim().Length < 4 ? ThreatLevel.High : ThreatLevel.Medium,
                    Reason = $"Starting {exe} actually runs \"{debugger}\" instead",
                    CanDisable = false
                });
            }
        }
        catch
        {
        }
    }

    // ───────────────────────── Evaluation ─────────────────────────

    private static void Evaluate(StartupItem item, ScanEngine engine, CancellationToken token)
    {
        if (item.Risk >= ThreatLevel.Medium) return; // already decided (Winlogon / IFEO)

        var expanded = Environment.ExpandEnvironmentVariables(item.Command);
        var program = item.FilePath ?? ExtractPath(expanded);
        var programName = program != null ? Path.GetFileName(program) : "";

        // Script hosts: the interesting file is the script in the arguments
        string? target = program;
        if (programName.Length > 0 && ScriptHosts.Contains(programName))
        {
            var lower = expanded.ToLowerInvariant();
            if (lower.Contains("http://") || lower.Contains("https://") || lower.Contains(" -enc") || lower.Contains("frombase64") ||
                lower.Contains("downloadstring") || lower.Contains("javascript:") || lower.Contains("vbscript:"))
            {
                item.Risk = ThreatLevel.High;
                item.Reason = $"Starts {programName} with a download or hidden encoded command";
                item.FilePath = program;
                return;
            }
            target = FindScriptArgument(expanded, program!) ?? program;
        }

        item.FilePath = target;
        item.FileExists = target != null && File.Exists(target);

        if (!item.FileExists)
        {
            item.Risk = ThreatLevel.Low;
            item.Reason = "The program it starts is missing (leftover entry)";
            return;
        }

        var verdict = engine.ScanFile(target!, ScanFileOptions.Default, token);
        if (verdict.IsThreat)
        {
            item.EngineDetection = verdict.Primary;
            item.Risk = verdict.MaxLevel;
            item.Reason = $"{verdict.Primary!.ThreatName}: {verdict.Primary.Details}";
            return;
        }

        item.Signature = SignatureVerifier.Check(target!);
        if (LooksUserWritable(target!) && item.Signature.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid)
        {
            var inTemp = target!.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase);
            item.Risk = inTemp ? ThreatLevel.Medium : ThreatLevel.Low;
            item.Reason = inTemp
                ? "Unsigned program starting from a temporary folder — a common malware trick"
                : "Unsigned program starting from your user folder (normal for many apps — check that you know it)";
            return;
        }

        item.Risk = ThreatLevel.None;
        item.Reason = item.Signature.Describe();
    }

    private static bool LooksUserWritable(string path) => FileClassifier.IsInUserWritableFolder(path);

    /// <summary>Pulls the program path out of a command line such as "C:\Program Files\App\app.exe" --tray.</summary>
    public static string? ExtractPath(string command)
    {
        command = Environment.ExpandEnvironmentVariables(command.Trim());
        if (command.Length == 0) return null;

        if (command.StartsWith(@"\??\")) command = command[4..];
        if (command.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            command = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), command[12..]);
        if (command.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
            command = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), command);

        string candidate;
        if (command.StartsWith('"'))
        {
            var end = command.IndexOf('"', 1);
            candidate = end > 1 ? command[1..end] : command.Trim('"');
        }
        else
        {
            candidate = command;
            var parts = command.Split(' ');
            var built = "";
            foreach (var part in parts)
            {
                built = built.Length == 0 ? part : built + " " + part;
                if (File.Exists(built) || ScanableExtensions.Any(e => built.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                {
                    candidate = built;
                    break;
                }
            }
            if (candidate == command && parts.Length > 0) candidate = parts[0];
        }

        candidate = candidate.Trim().TrimEnd(',');
        if (!Path.IsPathRooted(candidate))
        {
            var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), candidate);
            if (File.Exists(system)) return system;
            if (File.Exists(system + ".exe")) return system + ".exe";
            var windows = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), candidate);
            if (File.Exists(windows)) return windows;
        }
        return candidate;
    }

    private static string? FindScriptArgument(string command, string program)
    {
        var rest = command;
        var idx = rest.IndexOf(Path.GetFileName(program), StringComparison.OrdinalIgnoreCase);
        if (idx >= 0) rest = rest[(idx + Path.GetFileName(program).Length)..];

        foreach (var raw in SplitArgs(rest))
        {
            var token = raw.Trim('"', '\'', ' ');
            var comma = token.IndexOf(',');
            if (comma > 0) token = token[..comma]; // rundll32 file.dll,Entry
            if (ScanableExtensions.Any(e => token.EndsWith(e, StringComparison.OrdinalIgnoreCase)) && File.Exists(token)) return token;
        }
        return null;
    }

    private static IEnumerable<string> SplitArgs(string text)
    {
        var current = new System.Text.StringBuilder();
        var quoted = false;
        foreach (var c in text)
        {
            if (c == '"') { quoted = !quoted; continue; }
            if (c == ' ' && !quoted)
            {
                if (current.Length > 0) yield return current.ToString();
                current.Clear();
                continue;
            }
            current.Append(c);
        }
        if (current.Length > 0) yield return current.ToString();
    }

    // ───────────────────────── Disable / restore ─────────────────────────

    public static List<DisabledStartupEntry> ListDisabled() =>
        JsonStore.Load(AppPaths.DisabledStartupFile, () => new List<DisabledStartupEntry>());

    private static void SaveDisabled(List<DisabledStartupEntry> list) => JsonStore.Save(AppPaths.DisabledStartupFile, list);

    public static bool Disable(StartupItem item, out string message)
    {
        try
        {
            var entry = new DisabledStartupEntry
            {
                Source = item.Source,
                Name = item.Name,
                Location = item.Location,
                Command = item.Command
            };

            switch (item.Source)
            {
                case StartupSource.RegistryRun:
                {
                    var (hive, sub) = OpenHive(item.Location);
                    using var key = hive?.OpenSubKey(sub, writable: true);
                    if (key == null) { message = "Registry key not found"; return false; }
                    key.DeleteValue(item.Name == "(Default)" ? "" : item.Name, throwOnMissingValue: false);
                    break;
                }
                case StartupSource.StartupFolder:
                {
                    var folder = Path.Combine(AppPaths.BackupDir, "Startup");
                    Directory.CreateDirectory(folder);
                    var backup = Path.Combine(folder, entry.Id + "_" + Path.GetFileName(item.Command));
                    File.Move(item.Command, backup);
                    entry.BackupFile = backup;
                    break;
                }
                case StartupSource.ScheduledTask:
                {
                    if (!RunSchtasks($"/Change /TN \"{item.Location}\" /Disable", out var error)) { message = error; return false; }
                    break;
                }
                default:
                    message = "This item cannot be disabled from Kavach";
                    return false;
            }

            var list = ListDisabled();
            list.Add(entry);
            SaveDisabled(list);
            message = $"Disabled \"{item.Name}\"";
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            message = "Administrator rights are needed to disable this item";
            return false;
        }
        catch (System.Security.SecurityException)
        {
            message = "Administrator rights are needed to disable this item";
            return false;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }

    public static bool Restore(string entryId, out string message)
    {
        var list = ListDisabled();
        var entry = list.FirstOrDefault(e => e.Id == entryId);
        if (entry == null) { message = "Entry not found"; return false; }

        try
        {
            switch (entry.Source)
            {
                case StartupSource.RegistryRun:
                {
                    var (hive, sub) = OpenHive(entry.Location);
                    using var key = hive?.CreateSubKey(sub, writable: true);
                    if (key == null) { message = "Registry key not found"; return false; }
                    key.SetValue(entry.Name == "(Default)" ? "" : entry.Name, entry.Command);
                    break;
                }
                case StartupSource.StartupFolder:
                {
                    if (entry.BackupFile == null || !File.Exists(entry.BackupFile)) { message = "Backup file is missing"; return false; }
                    File.Move(entry.BackupFile, entry.Command, overwrite: true);
                    break;
                }
                case StartupSource.ScheduledTask:
                {
                    if (!RunSchtasks($"/Change /TN \"{entry.Location}\" /Enable", out var error)) { message = error; return false; }
                    break;
                }
            }

            list.Remove(entry);
            SaveDisabled(list);
            message = $"Restored \"{entry.Name}\"";
            return true;
        }
        catch (Exception ex)
        {
            message = ex is UnauthorizedAccessException ? "Administrator rights are needed" : ex.Message;
            return false;
        }
    }

    private static (RegistryKey? Hive, string SubKey) OpenHive(string location)
    {
        if (location.StartsWith(@"HKCU\")) return (Registry.CurrentUser, location[5..]);
        if (location.StartsWith(@"HKLM\")) return (Registry.LocalMachine, location[5..]);
        if (location.StartsWith(@"HKU\"))
        {
            return (Registry.Users, location[4..]); // HKU\SID\Software\...
        }
        return (null, location);
    }

    private static bool RunSchtasks(string arguments, out string error)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("schtasks.exe", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true
            });
            if (process == null) { error = "Could not start schtasks"; return false; }
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit(10_000);
            error = stderr.Trim();
            if (process.ExitCode != 0 && error.Length == 0) error = "schtasks failed (try running as administrator)";
            return process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
