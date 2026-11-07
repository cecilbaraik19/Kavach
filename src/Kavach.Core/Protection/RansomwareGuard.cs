using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;
using Kavach.Core.Native;
using Kavach.Core.Response;

namespace Kavach.Core.Protection;

/// <summary>
/// Ransomware protection.
///  • Puts hidden "bait" files in Documents, Desktop and Pictures. Real users never touch them,
///    but ransomware encrypts every file it finds — so a change to a bait file means an attack.
///  • Also watches for many files being renamed/changed in a few seconds (mass encryption).
///  • When triggered, it finds the program writing the most data, kills it and quarantines it.
/// </summary>
public sealed class RansomwareGuard : IDisposable
{
    private const string BaitPrefix = "!!!Kavach-Bait";
    private static readonly string[] BaitExtensions = { ".docx", ".xlsx", ".pdf", ".jpg" };

    private readonly KavachContext _ctx;
    private readonly Action<HostEvent> _raise;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, string> _baitHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<DateTime> _recentChanges = new();
    private readonly object _ioLock = new();
    private Dictionary<int, ulong> _lastIo = new();
    private Dictionary<int, ulong> _ioDelta = new();
    private Timer? _ioTimer;
    private DateTime _lastTrigger = DateTime.MinValue;
    private int _responding;

    public RansomwareGuard(KavachContext ctx, Action<HostEvent> raise)
    {
        _ctx = ctx;
        _raise = raise;
    }

    public bool IsRunning { get; private set; }
    public int BaitFileCount => _baitHashes.Count;

    public static bool IsBaitFile(string path) =>
        Path.GetFileName(path).StartsWith(BaitPrefix, StringComparison.OrdinalIgnoreCase);

    private static List<string> ProtectedFolders()
    {
        var folders = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
        };

        // As a service (SYSTEM) protect every user profile
        if (AdminHelper.IsLocalSystem())
        {
            try
            {
                var usersRoot = Path.GetDirectoryName(Path.GetDirectoryName(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)) ?? @"C:\Users\Public") ?? @"C:\Users";
                foreach (var userDir in Directory.EnumerateDirectories(usersRoot))
                {
                    var name = Path.GetFileName(userDir);
                    if (name is "Public" or "Default" or "Default User" or "All Users") continue;
                    folders.Add(Path.Combine(userDir, "Documents"));
                    folders.Add(Path.Combine(userDir, "Desktop"));
                    folders.Add(Path.Combine(userDir, "Pictures"));
                }
            }
            catch
            {
            }
        }

        return folders.Where(f => !string.IsNullOrWhiteSpace(f) && Directory.Exists(f))
                      .Distinct(StringComparer.OrdinalIgnoreCase)
                      .ToList();
    }

    public void Start()
    {
        if (IsRunning) return;
        foreach (var folder in ProtectedFolders())
        {
            PlaceBaitFiles(folder);
            Watch(folder);
        }

        // Keep a record of how much each process writes, so we can find the attacker quickly
        _ioTimer = new Timer(_ => SampleIo(), null, 0, 2000);
        IsRunning = true;
        _ctx.Log.Info("Ransomware", $"Ransomware protection started ({_baitHashes.Count} bait files)");
    }

    public void Stop()
    {
        if (!IsRunning) return;
        _ioTimer?.Dispose();
        _ioTimer = null;
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
        IsRunning = false;
        _ctx.Log.Warning("Ransomware", "Ransomware protection stopped");
    }

    /// <summary>Removes all bait files (used when the user turns the feature off).</summary>
    public void RemoveBaitFiles()
    {
        foreach (var path in _baitHashes.Keys.ToList())
        {
            try
            {
                if (File.Exists(path))
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                    File.Delete(path);
                }
            }
            catch
            {
            }
        }
        _baitHashes.Clear();
    }

    private void PlaceBaitFiles(string folder)
    {
        for (var i = 0; i < BaitExtensions.Length; i++)
        {
            var path = Path.Combine(folder, $"{BaitPrefix}-{i}{BaitExtensions[i]}");
            try
            {
                if (!File.Exists(path))
                {
                    File.WriteAllBytes(path, MakeBaitContent(BaitExtensions[i]));
                }
                File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
                _baitHashes[path] = HashDatabase.ComputeSha256(path) ?? "";
            }
            catch (Exception ex)
            {
                // Usually Windows "Controlled folder access" blocking Kavach
                _ctx.Log.Warning("Ransomware",
                    $"Could not place bait file in {folder} ({ex.Message}). If Windows Security → Ransomware protection → " +
                    "Controlled folder access is On, allow KavachService.exe there.");
                return;
            }
        }
    }

    /// <summary>Realistic-looking file content: correct file header plus random data.</summary>
    private static byte[] MakeBaitContent(string extension)
    {
        var body = RandomNumberGenerator.GetBytes(24 * 1024);
        byte[] header = extension switch
        {
            ".docx" or ".xlsx" => new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00 },
            ".pdf" => "%PDF-1.7\n"u8.ToArray(),
            ".jpg" => new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46 },
            _ => Array.Empty<byte>()
        };
        var content = new byte[header.Length + body.Length];
        Buffer.BlockCopy(header, 0, content, 0, header.Length);
        Buffer.BlockCopy(body, 0, content, header.Length, body.Length);
        return content;
    }

    private void Watch(string folder)
    {
        try
        {
            var watcher = new FileSystemWatcher(folder)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024
            };
            watcher.Changed += (_, e) => OnChange(e.FullPath, renamed: false);
            watcher.Deleted += (_, e) => OnChange(e.FullPath, renamed: false);
            watcher.Renamed += (_, e) => OnChange(e.OldFullPath, renamed: true, newPath: e.FullPath);
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            _ctx.Log.Warning("Ransomware", $"Cannot watch {folder}: {ex.Message}");
        }
    }

    private void OnChange(string path, bool renamed, string? newPath = null)
    {
        if (_baitHashes.ContainsKey(path))
        {
            // Bait touched: check it really changed (a backup program reading it is fine)
            var hash = File.Exists(path) ? HashDatabase.ComputeSha256(path) : null;
            if (renamed || hash == null || hash != _baitHashes[path])
            {
                Trigger($"Bait file was {(renamed ? "renamed" : hash == null ? "deleted" : "modified")}: {Path.GetFileName(path)}", path);
            }
            return;
        }

        // Mass rename detection: ransomware renames many files to a new extension (report.docx → report.docx.locked).
        // Normal saves and program builds write lots of files but rarely change extensions, so only those renames count.
        if (!renamed || newPath == null) return;
        var oldExt = Path.GetExtension(path);
        var newExt = Path.GetExtension(newPath);
        if (string.Equals(oldExt, newExt, StringComparison.OrdinalIgnoreCase)) return;
        if (newExt.Equals(".tmp", StringComparison.OrdinalIgnoreCase) || oldExt.Equals(".tmp", StringComparison.OrdinalIgnoreCase)) return;

        var now = DateTime.UtcNow;
        _recentChanges.Enqueue(now);
        while (_recentChanges.TryPeek(out var oldest) && now - oldest > TimeSpan.FromSeconds(5)) _recentChanges.TryDequeue(out _);
        if (_recentChanges.Count > 30)
        {
            Trigger($"{_recentChanges.Count} files renamed to a new extension in 5 seconds", null);
        }
    }

    private void SampleIo()
    {
        var current = new Dictionary<int, ulong>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id <= 4 || process.Id == Environment.ProcessId) continue;
                var bytes = NativeMethods.GetProcessWriteBytes(process.Id);
                if (bytes.HasValue) current[process.Id] = bytes.Value;
            }
            catch
            {
            }
            finally
            {
                process.Dispose();
            }
        }

        lock (_ioLock)
        {
            var delta = new Dictionary<int, ulong>();
            foreach (var kv in current)
            {
                if (_lastIo.TryGetValue(kv.Key, out var before) && kv.Value >= before) delta[kv.Key] = kv.Value - before;
            }
            _ioDelta = delta;
            _lastIo = current;
        }
    }

    private void Trigger(string reason, string? baitPath)
    {
        if (Interlocked.Exchange(ref _responding, 1) == 1) return;
        try
        {
            if (DateTime.UtcNow - _lastTrigger < TimeSpan.FromSeconds(10)) return;
            _lastTrigger = DateTime.UtcNow;

            _ctx.Log.Threat("Ransomware", "Possible ransomware activity: " + reason);

            // Take a fresh sample so we compare the last moments
            SampleIo();
            Thread.Sleep(300);
            SampleIo();

            Dictionary<int, ulong> delta;
            lock (_ioLock) delta = new Dictionary<int, ulong>(_ioDelta);

            var suspect = FindSuspect(delta, strongEvidence: baitPath != null);
            if (suspect != null)
            {
                var (pid, path) = suspect.Value;
                var name = Path.GetFileName(path);
                var killed = ProcessKiller.KillByPath(path);
                if (killed == 0) ProcessKiller.Kill(pid);

                var detection = new Detection
                {
                    FilePath = path,
                    ThreatName = "Ransomware.Behavior",
                    Level = ThreatLevel.Critical,
                    Source = DetectionSource.Ransomware,
                    ProcessId = pid,
                    Details = reason,
                    ActionTaken = "Process stopped"
                };

                var result = _ctx.Quarantine.Quarantine(path, detection.ThreatName, detection.Level);
                if (result.Success) detection.ActionTaken = "Process stopped and quarantined";

                _ctx.History.Add(new ScanSummary
                {
                    Type = ScanType.RealTime,
                    Status = ScanStatus.Completed,
                    Finished = DateTime.Now,
                    FilesScanned = 1,
                    ThreatsFound = 1,
                    Targets = { path },
                    Detections = { detection }
                });

                _raise(new HostEvent
                {
                    Kind = HostEventKind.RansomwareBlocked,
                    Title = "Ransomware attack stopped",
                    Message = $"{name} was trying to encrypt your files. Kavach stopped it" +
                              (result.Success ? " and moved it to quarantine." : "."),
                    Level = ThreatLevel.Critical,
                    Detection = detection
                });
            }
            else
            {
                _raise(new HostEvent
                {
                    Kind = HostEventKind.RansomwareBlocked,
                    Title = "Possible ransomware activity",
                    Message = reason + ". Kavach could not identify the program — run a Full scan now.",
                    Level = ThreatLevel.High
                });
            }

            // Put fresh bait back
            if (baitPath != null)
            {
                try
                {
                    if (File.Exists(baitPath))
                    {
                        File.SetAttributes(baitPath, FileAttributes.Normal);
                        File.Delete(baitPath); // replace the damaged bait with a fresh one
                    }
                }
                catch
                {
                }
                var folder = Path.GetDirectoryName(baitPath);
                if (folder != null) PlaceBaitFiles(folder);
            }
        }
        catch (Exception ex)
        {
            _ctx.Log.Error("Ransomware", ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _responding, 0);
        }
    }

    /// <summary>The program that wrote the most data recently, ignoring trusted Windows components.</summary>
    private (int Pid, string Path)? FindSuspect(Dictionary<int, ulong> delta, bool strongEvidence)
    {
        foreach (var (pid, bytes) in delta.OrderByDescending(kv => kv.Value))
        {
            if (bytes < 256 * 1024) break; // too little writing to be mass encryption
            var path = NativeMethods.GetProcessImagePath(pid);
            if (path == null || AppPaths.IsOwnPath(path)) continue;

            // Windows itself (search indexer, explorer copying files, updates) is trusted if signed
            if (FileClassifier.IsInTrustedInstallFolder(path) && SignatureVerifier.Check(path).IsTrusted) continue;

            // Programs the user has allowed are never blamed
            if (_ctx.Settings.IsHashAllowed(HashDatabase.ComputeSha256(path))) continue;

            // Without a touched bait file the evidence is weaker: do not blame digitally signed programs
            // (build tools, installers, backup and sync software)
            if (!strongEvidence && SignatureVerifier.Check(path).IsTrusted) continue;

            var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (path.StartsWith(windowsDir + "\\", StringComparison.OrdinalIgnoreCase) && !path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)) continue;

            return (pid, path);
        }
        return null;
    }

    public void Dispose() => Stop();
}
