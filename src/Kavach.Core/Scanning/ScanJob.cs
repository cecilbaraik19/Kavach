using System.Collections.Concurrent;
using System.Diagnostics;
using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;
using Kavach.Core.SystemChecks;

namespace Kavach.Core.Scanning;

/// <summary>
/// Runs one scan (Quick, Full, Custom, Processes, System, USB or Scheduled) on background threads.
/// Supports pause, resume and cancel, and reports live progress.
/// </summary>
public sealed class ScanJob
{
    private readonly KavachContext _ctx;
    private readonly List<ScanTarget> _targets = new();
    private readonly List<string> _singleFiles = new();
    private readonly ManualResetEventSlim _gate = new(true);
    private readonly CancellationTokenSource _cts = new();
    private readonly Stopwatch _clock = new();
    private readonly object _detectionLock = new();

    private int _scanned, _skipped, _discovered, _threats;
    private volatile bool _discoveryDone;
    private volatile string _current = "";

    public ScanJob(KavachContext ctx, ScanType type, IEnumerable<string>? customPaths = null)
    {
        _ctx = ctx;
        Type = type;
        Summary = new ScanSummary { Type = type };

        switch (type)
        {
            case ScanType.Quick:
            case ScanType.Scheduled:
                _targets.AddRange(ScanLocations.Quick());
                IncludeProcesses = true;
                IncludeSystemChecks = true;
                OnlyInterestingFiles = true;
                break;
            case ScanType.Full:
                _targets.AddRange(ScanLocations.Full());
                IncludeProcesses = true;
                IncludeSystemChecks = true;
                OnlyInterestingFiles = true;
                break;
            case ScanType.Processes:
                IncludeProcesses = true;
                break;
            case ScanType.System:
                IncludeSystemChecks = true;
                break;
            default: // Custom, Usb, RealTime
                foreach (var p in customPaths ?? Enumerable.Empty<string>())
                {
                    if (File.Exists(p)) _singleFiles.Add(p);
                    else if (Directory.Exists(p)) _targets.Add(new ScanTarget(p, type == ScanType.Usb ? 6 : -1));
                }
                break;
        }

        Summary.Targets = _targets.Select(t => t.Path).Concat(_singleFiles).ToList();
        if (IncludeProcesses) Summary.Targets.Add("Running programs");
        if (IncludeSystemChecks) Summary.Targets.Add("Startup items and hosts file");
    }

    public ScanType Type { get; }
    public ScanSummary Summary { get; }
    public bool IncludeProcesses { get; set; }
    public bool IncludeSystemChecks { get; set; }
    public bool OnlyInterestingFiles { get; set; }
    /// <summary>Wait while a full-screen game/video runs or on battery (used by schedules and USB scans).</summary>
    public bool PauseWhenBusy { get; set; }
    /// <summary>Use the scan cache (turned off for "scan this file now").</summary>
    public bool UseCache { get; set; } = true;

    public bool IsPaused => !_gate.IsSet;
    public bool IsRunning { get; private set; }

    public event Action<ScanProgress>? ProgressChanged;
    public event Action<Detection>? ThreatFound;

    public void Pause() => _gate.Reset();
    public void Resume() => _gate.Set();

    public void Cancel()
    {
        _cts.Cancel();
        _gate.Set();
    }

    public ScanProgress CurrentProgress => new(_scanned, _skipped, _threats, _discovered, _discoveryDone, _current, _clock.Elapsed);

    public Task<ScanSummary> RunAsync(CancellationToken external = default)
    {
        var linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, external);
        return Task.Run(() => Run(linked.Token));
    }

    private ScanSummary Run(CancellationToken token)
    {
        IsRunning = true;
        _clock.Start();
        _ctx.Log.Info("Scan", $"{Type} scan started");

        using var progressTimer = new Timer(_ => ProgressChanged?.Invoke(CurrentProgress), null, 250, 250);

        try
        {
            if (IncludeProcesses) ScanProcesses(token);
            if (_targets.Count > 0 || _singleFiles.Count > 0) ScanFiles(token);
            else _discoveryDone = true;
            if (IncludeSystemChecks) ScanSystem(token);

            Summary.Status = ScanStatus.Completed;
        }
        catch (OperationCanceledException)
        {
            Summary.Status = ScanStatus.Cancelled;
        }
        catch (Exception ex)
        {
            Summary.Status = ScanStatus.Failed;
            Summary.Error = ex.Message;
            _ctx.Log.Error("Scan", $"{Type} scan failed: {ex.Message}");
        }
        finally
        {
            _clock.Stop();
            IsRunning = false;
            _discoveryDone = true;
            _current = "";
            Summary.Finished = DateTime.Now;
            Summary.FilesScanned = _scanned;
            Summary.FilesSkipped = _skipped;
            Summary.ThreatsFound = Summary.Detections.Count;
            _ctx.Cache.Save();
            Finish();
            ProgressChanged?.Invoke(CurrentProgress);
        }
        return Summary;
    }

    private void Finish()
    {
        if (Type != ScanType.RealTime) _ctx.History.Add(Summary);

        if (Summary.Status == ScanStatus.Completed)
        {
            if (Type is ScanType.Quick or ScanType.Scheduled) _ctx.Settings.Update(s => s.LastQuickScan = DateTime.Now);
            if (Type == ScanType.Full) _ctx.Settings.Update(s => s.LastFullScan = DateTime.Now);
        }

        var text = $"{Type} scan {Summary.Status.ToString().ToLowerInvariant()}: {Summary.FilesScanned:N0} files scanned, " +
                   $"{Summary.ThreatsFound} threat(s) found in {Summary.Duration:hh\\:mm\\:ss}";
        if (Summary.ThreatsFound > 0) _ctx.Log.Threat("Scan", text);
        else _ctx.Log.Info("Scan", text);
    }

    private void Report(Detection detection)
    {
        lock (_detectionLock)
        {
            // The same file can be found by more than one method; keep them all but count the file once
            Summary.Detections.Add(detection);
            _threats = Summary.Detections.Select(d => d.FilePath + "|" + d.InnerPath).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        }
        ThreatFound?.Invoke(detection);
    }

    private void WaitIfNeeded(CancellationToken token)
    {
        _gate.Wait(token);
        token.ThrowIfCancellationRequested();

        if (!PauseWhenBusy) return;
        var settings = _ctx.Settings.Current;
        while ((settings.PauseWhenFullscreen && SystemState.IsUserBusyFullscreen()) ||
               (settings.PauseOnBattery && SystemState.IsOnBattery()))
        {
            _current = "Waiting — PC is busy or on battery";
            Task.Delay(5000, token).Wait(token);
        }
    }

    // ───────────────────────── Files ─────────────────────────

    private void ScanFiles(CancellationToken token)
    {
        var settings = _ctx.Settings.Current;
        var queue = new BlockingCollection<string>(boundedCapacity: 10_000);
        var options = UseCache
            ? (OnlyInterestingFiles ? ScanFileOptions.Interesting : ScanFileOptions.Default)
            : ScanFileOptions.NoCache;

        var workerCount = SystemState.WorkerCount(settings.Performance);
        var priority = settings.Performance switch
        {
            PerformanceMode.Low => ThreadPriority.Lowest,
            PerformanceMode.Balanced => ThreadPriority.BelowNormal,
            _ => ThreadPriority.Normal
        };
        var delayMs = settings.Performance == PerformanceMode.Low ? 5 : 0;

        Exception? workerError = null;
        var workers = new List<Thread>();
        for (var i = 0; i < workerCount; i++)
        {
            var thread = new Thread(() =>
            {
                try
                {
                    foreach (var path in queue.GetConsumingEnumerable(token))
                    {
                        WaitIfNeeded(token);
                        _current = path;
                        var verdict = _ctx.Engine.ScanFile(path, options, token);
                        if (verdict.Skipped) Interlocked.Increment(ref _skipped);
                        else Interlocked.Increment(ref _scanned);
                        foreach (var d in verdict.Detections) Report(d);
                        if (delayMs > 0) Thread.Sleep(delayMs);
                    }
                }
                catch (OperationCanceledException)
                {
                }
                catch (Exception ex)
                {
                    workerError = ex;
                }
            })
            {
                IsBackground = true,
                Priority = priority,
                Name = "Kavach scan worker " + i
            };
            workers.Add(thread);
            thread.Start();
        }

        try
        {
            foreach (var file in _singleFiles)
            {
                queue.Add(file, token);
                Interlocked.Increment(ref _discovered);
            }
            foreach (var target in _targets) Enumerate(target, queue, token);
        }
        finally
        {
            _discoveryDone = true;
            queue.CompleteAdding();
            foreach (var w in workers) w.Join();
        }

        token.ThrowIfCancellationRequested();
        if (workerError != null) _ctx.Log.Warning("Scan", "A scan worker stopped: " + workerError.Message);
    }

    private static readonly EnumerationOptions DirOptions = new()
    {
        IgnoreInaccessible = true,
        RecurseSubdirectories = false,
        AttributesToSkip = FileAttributes.ReparsePoint, // avoid junction loops; hidden/system folders are still scanned
        ReturnSpecialDirectories = false
    };

    private static readonly EnumerationOptions FileEnumOptions = new()
    {
        IgnoreInaccessible = true,
        RecurseSubdirectories = false,
        AttributesToSkip = 0
    };

    private void Enumerate(ScanTarget target, BlockingCollection<string> queue, CancellationToken token)
    {
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((target.Path, 0));

        while (stack.Count > 0)
        {
            WaitIfNeeded(token);
            var (dir, depth) = stack.Pop();
            if (AppPaths.IsOwnPath(dir) || _ctx.Settings.IsExcluded(dir)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", FileEnumOptions))
                {
                    queue.Add(file, token);
                    Interlocked.Increment(ref _discovered);
                }

                if (target.MaxDepth < 0 || depth < target.MaxDepth)
                {
                    foreach (var sub in Directory.EnumerateDirectories(dir, "*", DirOptions))
                    {
                        if (!ScanLocations.IsSkippedFolder(sub)) stack.Push((sub, depth + 1));
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    // ───────────────────────── Processes ─────────────────────────

    private void ScanProcesses(CancellationToken token)
    {
        _current = "Running programs";
        var detections = ProcessScanner.ScanRunning(_ctx.Engine, token, path =>
        {
            _current = path;
            Interlocked.Increment(ref _scanned);
            Interlocked.Increment(ref _discovered);
            WaitIfNeeded(token);
        });
        foreach (var d in detections) Report(d);
    }

    // ───────────────────────── Startup items and hosts file ─────────────────────────

    private void ScanSystem(CancellationToken token)
    {
        _current = "Startup items";
        foreach (var item in StartupScanner.Scan(_ctx.Engine, token))
        {
            Interlocked.Increment(ref _scanned);
            var detection = item.ToDetection();
            if (detection != null) Report(detection);
        }

        token.ThrowIfCancellationRequested();
        _current = "Hosts file";
        var hosts = HostsFileChecker.Check();
        Interlocked.Increment(ref _scanned);
        foreach (var d in hosts.Detections) Report(d);
    }
}
