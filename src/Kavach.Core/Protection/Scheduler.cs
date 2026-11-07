using Kavach.Core.Infrastructure;
using Kavach.Core.Scanning;

namespace Kavach.Core.Protection;

/// <summary>
/// Runs scheduled scans (daily / weekly). If the PC was off at the planned time, the scan runs
/// as soon as Kavach starts. Scans wait while on battery or while a full-screen game/video runs.
/// </summary>
public sealed class Scheduler : IDisposable
{
    private readonly KavachContext _ctx;
    private readonly Action<HostEvent> _raise;
    private Timer? _timer;
    private int _busy;
    private DateTime _lastBatteryNotice = DateTime.MinValue;

    public Scheduler(KavachContext ctx, Action<HostEvent> raise)
    {
        _ctx = ctx;
        _raise = raise;
    }

    public ScanJob? CurrentJob { get; private set; }
    public event Action<ScanJob>? JobStarted;

    public void Start()
    {
        _timer ??= new Timer(_ => Check(), null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(30));
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
        CurrentJob?.Cancel();
    }

    private void Check()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var now = DateTime.Now;
            var due = _ctx.Settings.Current.Schedules
                .Where(s => s.Enabled && s.NextRun(now) <= now)
                .OrderBy(s => s.NextRun(now))
                .FirstOrDefault();
            if (due == null) return;

            if (due.SkipOnBattery && SystemState.IsOnBattery())
            {
                if (now - _lastBatteryNotice > TimeSpan.FromHours(1))
                {
                    _ctx.Log.Info("Schedule", $"\"{due.Name}\" is waiting until the PC is plugged in");
                    _lastBatteryNotice = now;
                }
                return;
            }

            Run(due);
        }
        catch (Exception ex)
        {
            _ctx.Log.Error("Schedule", ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _busy, 0);
        }
    }

    private void Run(ScheduleEntry entry)
    {
        _ctx.Settings.Update(s =>
        {
            var e = s.Schedules.FirstOrDefault(x => x.Id == entry.Id);
            if (e != null) e.LastRun = DateTime.Now;
        });

        var type = entry.ScanType == ScanType.Full ? ScanType.Full : ScanType.Scheduled;
        var job = new ScanJob(_ctx, type) { PauseWhenBusy = true };
        if (type == ScanType.Full) job.PauseWhenBusy = true;
        CurrentJob = job;
        JobStarted?.Invoke(job);

        _ctx.Log.Info("Schedule", $"Scheduled scan \"{entry.Name}\" started");
        _raise(new HostEvent
        {
            Kind = HostEventKind.ScheduledScanStarted,
            Title = "Scheduled scan started",
            Message = $"\"{entry.Name}\" is running in the background."
        });

        var summary = job.RunAsync().GetAwaiter().GetResult();
        CurrentJob = null;

        var quarantined = 0;
        if (_ctx.Settings.Current.AutoQuarantine)
        {
            foreach (var group in summary.Detections.Where(d => File.Exists(d.FilePath))
                         .GroupBy(d => d.FilePath, StringComparer.OrdinalIgnoreCase))
            {
                var worst = group.OrderByDescending(d => d.Level).First();
                if (worst.Level < ThreatLevel.High || worst.Source == DetectionSource.Hosts) continue;
                var result = _ctx.Quarantine.Quarantine(group.Key, worst.ThreatName, worst.Level);
                if (!result.Success) continue;
                quarantined++;
                foreach (var d in group) _ctx.History.UpdateDetectionAction(d.Id, "Quarantined");
            }
        }

        _raise(new HostEvent
        {
            Kind = HostEventKind.ScheduledScanFinished,
            Title = summary.ThreatsFound > 0 ? "Scheduled scan found threats" : "Scheduled scan finished",
            Message = summary.ThreatsFound > 0
                ? $"{summary.ThreatsFound} threat(s) found" + (quarantined > 0 ? $", {quarantined} quarantined." : ". Open Kavach to review.")
                : $"No threats found in {summary.FilesScanned:N0} items.",
            Level = summary.Detections.Count > 0 ? summary.Detections.Max(d => d.Level) : ThreatLevel.None
        });
    }

    public void Dispose() => Stop();
}
