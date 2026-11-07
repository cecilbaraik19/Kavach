using System.Collections.Concurrent;
using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;
using Kavach.Core.Response;

namespace Kavach.Core.Protection;

/// <summary>
/// Real-time file protection. Watches Downloads, Desktop, Documents, Temp, USB drives and any
/// extra folders, and scans every new or changed file as soon as it is finished writing.
/// </summary>
public sealed class RealTimeMonitor : IDisposable
{
    private static readonly HashSet<string> PartialDownloadExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload", ".!ut", ".aria2"
    };

    private readonly KavachContext _ctx;
    private readonly Action<HostEvent> _raise;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTime> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recentlyScanned = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _extraRoots = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;
    private int _processing;

    public RealTimeMonitor(KavachContext ctx, Action<HostEvent> raise)
    {
        _ctx = ctx;
        _raise = raise;
    }

    public bool IsRunning { get; private set; }
    public IReadOnlyList<string> WatchedFolders => _watchers.Select(w => w.Path).ToList();

    /// <summary>Called by the ransomware guard so its bait files are not scanned.</summary>
    public Func<string, bool>? IgnorePath { get; set; }

    public static List<string> DefaultFolders(KavachSettings settings)
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var folders = new List<string>
        {
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };
        folders.AddRange(settings.ExtraMonitoredFolders);
        return folders.Where(f => !string.IsNullOrWhiteSpace(f) && Directory.Exists(f))
                      .Distinct(StringComparer.OrdinalIgnoreCase)
                      .ToList();
    }

    /// <summary>When Kavach runs as a service (SYSTEM), watch every user's folders.</summary>
    private static List<string> AllUserFolders()
    {
        var list = new List<string>();
        var usersRoot = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)) ?? @"C:\Users\Public";
        var root = Path.GetDirectoryName(usersRoot) ?? @"C:\Users";
        try
        {
            foreach (var userDir in Directory.EnumerateDirectories(root))
            {
                var name = Path.GetFileName(userDir);
                if (name is "Public" or "Default" or "Default User" or "All Users") continue;
                foreach (var sub in new[] { "Downloads", "Desktop", "Documents", @"AppData\Local\Temp",
                             @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
                {
                    var p = Path.Combine(userDir, sub);
                    if (Directory.Exists(p)) list.Add(p);
                }
            }
        }
        catch
        {
        }
        return list;
    }

    public void Start()
    {
        if (IsRunning) return;
        var settings = _ctx.Settings.Current;
        var folders = DefaultFolders(settings);
        if (AdminHelper.IsLocalSystem()) folders.AddRange(AllUserFolders());
        folders.AddRange(_extraRoots);

        foreach (var folder in folders.Distinct(StringComparer.OrdinalIgnoreCase)) AddWatcher(folder);

        _timer = new Timer(_ => ProcessPending(), null, 500, 500);
        IsRunning = true;
        _ctx.Log.Info("Real-time", $"Real-time protection started ({_watchers.Count} folders watched)");
    }

    public void Stop()
    {
        if (!IsRunning) return;
        _timer?.Dispose();
        _timer = null;
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();
        _pending.Clear();
        IsRunning = false;
        _ctx.Log.Warning("Real-time", "Real-time protection stopped");
    }

    /// <summary>Start watching a USB drive or other folder while protection is running.</summary>
    public void AddRoot(string folder)
    {
        _extraRoots.Add(folder);
        if (IsRunning) AddWatcher(folder);
    }

    public void RemoveRoot(string folder)
    {
        _extraRoots.Remove(folder);
        var watcher = _watchers.FirstOrDefault(w => string.Equals(w.Path, folder, StringComparison.OrdinalIgnoreCase));
        if (watcher == null) return;
        watcher.EnableRaisingEvents = false;
        watcher.Dispose();
        _watchers.Remove(watcher);
    }

    private void AddWatcher(string folder)
    {
        if (_watchers.Any(w => string.Equals(w.Path, folder, StringComparison.OrdinalIgnoreCase))) return;
        try
        {
            var watcher = new FileSystemWatcher(folder)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024
            };
            watcher.Created += (_, e) => Queue(e.FullPath);
            watcher.Changed += (_, e) => Queue(e.FullPath);
            watcher.Renamed += (_, e) => Queue(e.FullPath);
            watcher.Error += (_, e) => _ctx.Log.Warning("Real-time", $"Watcher error on {folder}: {e.GetException().Message}");
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            _ctx.Log.Warning("Real-time", $"Cannot watch {folder}: {ex.Message}");
        }
    }

    private void Queue(string path)
    {
        if (PartialDownloadExtensions.Contains(Path.GetExtension(path))) return;
        if (AppPaths.IsOwnPath(path)) return;
        if (IgnorePath?.Invoke(path) == true) return;
        _pending[path] = DateTime.UtcNow;
    }

    /// <summary>Scan files that have been quiet for 1.5 seconds (finished downloading/copying).</summary>
    private void ProcessPending()
    {
        if (Interlocked.Exchange(ref _processing, 1) == 1) return;
        try
        {
            var now = DateTime.UtcNow;
            foreach (var kv in _pending)
            {
                if (now - kv.Value < TimeSpan.FromSeconds(1.5)) continue;
                if (!_pending.TryRemove(kv.Key, out _)) continue;
                ScanOne(kv.Key);
            }

            // Forget old "recently scanned" entries
            foreach (var kv in _recentlyScanned)
            {
                if (now - kv.Value > TimeSpan.FromMinutes(2)) _recentlyScanned.TryRemove(kv.Key, out _);
            }
        }
        catch (Exception ex)
        {
            _ctx.Log.Error("Real-time", ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _processing, 0);
        }
    }

    private void ScanOne(string path)
    {
        if (!File.Exists(path)) return;
        if (!WaitUntilReadable(path)) return;

        var info = new FileInfo(path);
        var stamp = info.LastWriteTimeUtc;
        if (_recentlyScanned.TryGetValue(path, out var last) && last == stamp) return;
        _recentlyScanned[path] = stamp;

        var verdict = _ctx.Engine.ScanFile(path, ScanFileOptions.RealTime);
        if (verdict.IsThreat)
        {
            HandleThreat(verdict);
            return;
        }

        if (_ctx.Settings.Current.DownloadWarnings && IsNewProgramDownload(path))
        {
            var sig = SignatureVerifier.Check(path);
            _raise(new HostEvent
            {
                Kind = HostEventKind.DownloadWarning,
                Title = "New program downloaded",
                Message = $"{Path.GetFileName(path)} — scanned clean. {sig.Describe()}." +
                          (sig.Status == SignatureStatus.Valid ? "" : " Only run it if you trust where it came from."),
                Level = sig.Status == SignatureStatus.Valid ? ThreatLevel.None : ThreatLevel.Low
            });
            _ctx.Log.Info("Downloads", $"New program downloaded: {path} ({sig.Describe()})");
        }
    }

    private void HandleThreat(FileVerdict verdict)
    {
        var primary = verdict.Primary!;
        var settings = _ctx.Settings.Current;
        _ctx.Log.Threat("Real-time", $"{primary.ThreatName} found in {verdict.Path}");

        var summary = new ScanSummary
        {
            Type = ScanType.RealTime,
            Status = ScanStatus.Completed,
            Finished = DateTime.Now,
            FilesScanned = 1,
            ThreatsFound = 1,
            Targets = { verdict.Path },
            Detections = verdict.Detections.ToList()
        };

        if (settings.AutoQuarantine)
        {
            var killed = ProcessKiller.KillByPath(verdict.Path);
            var result = _ctx.Quarantine.Quarantine(verdict.Path, primary.ThreatName, primary.Level);
            foreach (var d in verdict.Detections) d.ActionTaken = result.Success ? "Quarantined" : "Quarantine failed";
            _ctx.History.Add(summary);

            _raise(new HostEvent
            {
                Kind = result.Success ? HostEventKind.ThreatQuarantined : HostEventKind.ThreatDetected,
                Title = result.Success ? "Threat blocked" : "Threat found",
                Message = $"{primary.ThreatName} in {Path.GetFileName(verdict.Path)}. " +
                          (result.Success ? "It was moved to quarantine." : result.Message) +
                          (killed > 0 ? $" Stopped {killed} running copy." : ""),
                Level = primary.Level,
                Detection = primary
            });
        }
        else
        {
            _ctx.History.Add(summary);
            _raise(new HostEvent
            {
                Kind = HostEventKind.ThreatDetected,
                Title = "Threat found",
                Message = $"{primary.ThreatName} in {verdict.Path}. Open Kavach to quarantine it.",
                Level = primary.Level,
                Detection = primary
            });
        }
    }

    private static bool IsNewProgramDownload(string path)
    {
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var inDownloads = path.StartsWith(downloads, StringComparison.OrdinalIgnoreCase)
                          || path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase);
        return inDownloads && (FileClassifier.IsExecutable(path) || FileClassifier.IsScript(path));
    }

    private static bool WaitUntilReadable(string path)
    {
        for (var i = 0; i < 20; i++)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                return true;
            }
            catch (FileNotFoundException)
            {
                return false;
            }
            catch (DirectoryNotFoundException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (IOException)
            {
                Thread.Sleep(250); // still being written
            }
        }
        return true; // locked for long: try anyway with shared access
    }

    public void Dispose() => Stop();
}
