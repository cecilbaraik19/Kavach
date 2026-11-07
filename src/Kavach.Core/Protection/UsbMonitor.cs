using Kavach.Core.Scanning;

namespace Kavach.Core.Protection;

/// <summary>
/// Notices when a pen drive / USB disk is plugged in, checks it for a malicious autorun.inf
/// and scans it automatically.
/// </summary>
public sealed class UsbMonitor : IDisposable
{
    private readonly KavachContext _ctx;
    private readonly Action<HostEvent> _raise;
    private readonly RealTimeMonitor? _realTime;
    private HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;
    private int _busy;

    public UsbMonitor(KavachContext ctx, Action<HostEvent> raise, RealTimeMonitor? realTime)
    {
        _ctx = ctx;
        _raise = raise;
        _realTime = realTime;
    }

    public bool IsRunning { get; private set; }

    public void Start()
    {
        if (IsRunning) return;
        _known = CurrentRemovableDrives();
        foreach (var drive in _known) _realTime?.AddRoot(drive);
        _timer = new Timer(_ => Poll(), null, 3000, 3000);
        IsRunning = true;
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
        IsRunning = false;
    }

    private static HashSet<string> CurrentRemovableDrives()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType == DriveType.Removable && d.IsReady) set.Add(d.RootDirectory.FullName);
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
        return set;
    }

    private void Poll()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var now = CurrentRemovableDrives();
            foreach (var removed in _known.Where(k => !now.Contains(k)).ToList()) _realTime?.RemoveRoot(removed);

            var added = now.Where(d => !_known.Contains(d)).ToList();
            _known = now;
            foreach (var drive in added) OnInserted(drive);
        }
        finally
        {
            Interlocked.Exchange(ref _busy, 0);
        }
    }

    private void OnInserted(string root)
    {
        string label;
        try { label = new DriveInfo(root).VolumeLabel; } catch { label = ""; }
        var display = string.IsNullOrEmpty(label) ? root : $"{label} ({root.TrimEnd('\\')})";

        _ctx.Log.Info("USB", $"USB drive inserted: {display}");
        _realTime?.AddRoot(root);

        CheckAutorun(root);

        if (!_ctx.Settings.Current.UsbAutoScan) return;

        _raise(new HostEvent
        {
            Kind = HostEventKind.UsbInserted,
            Title = "Scanning USB drive",
            Message = $"Kavach is checking {display} for threats…"
        });

        var job = new ScanJob(_ctx, ScanType.Usb, new[] { root }) { PauseWhenBusy = false };
        var summary = job.RunAsync().GetAwaiter().GetResult();

        if (summary.Detections.Count == 0)
        {
            _raise(new HostEvent
            {
                Kind = HostEventKind.UsbInserted,
                Title = "USB drive is safe",
                Message = $"{display}: {summary.FilesScanned:N0} files scanned, no threats found."
            });
            return;
        }

        var quarantined = 0;
        if (_ctx.Settings.Current.AutoQuarantine)
        {
            foreach (var group in summary.Detections.GroupBy(d => d.FilePath, StringComparer.OrdinalIgnoreCase))
            {
                var worst = group.OrderByDescending(d => d.Level).First();
                if (worst.Level < ThreatLevel.Medium) continue;
                var result = _ctx.Quarantine.Quarantine(group.Key, worst.ThreatName, worst.Level);
                if (result.Success)
                {
                    quarantined++;
                    foreach (var d in group)
                    {
                        d.ActionTaken = "Quarantined";
                        _ctx.History.UpdateDetectionAction(d.Id, "Quarantined");
                    }
                }
            }
        }

        var first = summary.Detections.OrderByDescending(d => d.Level).First();
        _raise(new HostEvent
        {
            Kind = HostEventKind.ThreatDetected,
            Title = "Threats on USB drive",
            Message = $"{display}: {summary.ThreatsFound} threat(s) found" +
                      (quarantined > 0 ? $", {quarantined} moved to quarantine." : ". Open Kavach to review them."),
            Level = first.Level,
            Detection = first
        });
    }

    /// <summary>autorun.inf that starts a program is how many USB worms spread.</summary>
    private void CheckAutorun(string root)
    {
        var path = Path.Combine(root, "autorun.inf");
        try
        {
            if (!File.Exists(path)) return;
            var text = File.ReadAllText(path).ToLowerInvariant();
            var runs = text.Contains("open=") || text.Contains("shellexecute=") || text.Contains("shell\\open\\command=") ||
                       text.Contains("shell\\explore\\command=");
            if (!runs) return;

            var detection = new Detection
            {
                FilePath = path,
                ThreatName = "Worm.Autorun.USB",
                Level = ThreatLevel.High,
                Source = DetectionSource.Usb,
                Details = "autorun.inf on a USB drive tries to start a program automatically"
            };
            _ctx.Log.Threat("USB", $"Suspicious autorun.inf on {root}");

            if (_ctx.Settings.Current.AutoQuarantine)
            {
                var result = _ctx.Quarantine.Quarantine(path, detection.ThreatName, detection.Level);
                detection.ActionTaken = result.Success ? "Quarantined" : "Quarantine failed";
            }

            _raise(new HostEvent
            {
                Kind = HostEventKind.ThreatDetected,
                Title = "USB autorun blocked",
                Message = $"A suspicious autorun.inf was found on {root}. " +
                          (detection.ActionTaken == "Quarantined" ? "It was moved to quarantine." : "Open Kavach to remove it."),
                Level = ThreatLevel.High,
                Detection = detection
            });
        }
        catch
        {
        }
    }

    public void Dispose() => Stop();
}
