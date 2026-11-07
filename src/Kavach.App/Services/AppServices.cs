using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Kavach.Core;
using Kavach.Core.Infrastructure;
using Kavach.Core.Protection;
using Kavach.Core.Scanning;

namespace Kavach.App.Services;

public enum ProtectionLevel
{
    Protected,
    Attention,
    AtRisk
}

public sealed record ProtectionStatus(ProtectionLevel Level, string Title, string Message);

/// <summary>
/// Shared state of the Kavach app: the engine, where protection runs (service or app),
/// the running scan and recent alerts.
/// </summary>
public static class AppServices
{
    private static Dispatcher? _dispatcher;
    private static DispatcherTimer? _fallbackTimer;

    public static KavachContext Context { get; private set; } = null!;
    public static SignatureUpdater Updater { get; private set; } = null!;
    public static AppUpdater AppUpdater { get; private set; } = null!;

    /// <summary>A newer Kavach found by the automatic check (shown on the About page).</summary>
    public static AppUpdater.ReleaseInfo? AvailableUpdate { get; set; }

    /// <summary>Protection running inside this app (only when the Kavach service is not installed/running).</summary>
    public static ProtectionHost? LocalHost { get; private set; }
    public static EventPipeClient? ServiceClient { get; private set; }
    public static bool ServiceConnected => ServiceClient?.IsConnected == true;

    public static ObservableCollection<HostEvent> RecentEvents { get; } = new();

    public static ScanJob? ActiveScan { get; private set; }
    public static event Action? ActiveScanChanged;
    public static event Action? StatusChanged;
    public static event Action<HostEvent>? HostEventReceived;
    public static event Action<string, bool>? ToastRequested;

    public static bool IsAdmin { get; } = AdminHelper.IsAdministrator();

    public static void Initialize(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        Context = KavachContext.Create();
        Updater = new SignatureUpdater(Context);
        AppUpdater = new AppUpdater(Context);
        StartAutomaticUpdateCheck();

        Context.Quarantine.Changed += RaiseStatus;
        Context.History.Changed += RaiseStatus;
        Context.Settings.Changed += _ => RaiseStatus();
        Context.SignaturesReloaded += RaiseStatus;

        // Use the Windows service if it is running; otherwise protect from inside the app.
        ServiceClient = new EventPipeClient();
        ServiceClient.EventReceived += OnHostEvent;
        ServiceClient.ConnectionChanged += OnServiceConnectionChanged;

        if (EventPipeClient.IsServiceRunning())
        {
            ServiceClient.Start();
        }
        else
        {
            StartLocalProtection();
            ServiceClient.Start(); // keeps trying; switches over if the service starts later
        }
    }

    private static void StartLocalProtection()
    {
        if (LocalHost != null) return;
        LocalHost = new ProtectionHost(Context, isService: false);
        LocalHost.EventRaised += OnHostEvent;
        LocalHost.Start();
        RaiseStatus();
    }

    private static void StopLocalProtection()
    {
        if (LocalHost == null) return;
        LocalHost.EventRaised -= OnHostEvent;
        LocalHost.Dispose();
        LocalHost = null;
        RaiseStatus();
    }

    private static void OnServiceConnectionChanged(bool connected)
    {
        Run(() =>
        {
            if (connected)
            {
                _fallbackTimer?.Stop();
                StopLocalProtection();
                Context.Log.Info("App", "Connected to the Kavach service");
            }
            else
            {
                // Give the service 15 seconds to come back (e.g. restarting) before protecting from the app
                _fallbackTimer?.Stop();
                _fallbackTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
                _fallbackTimer.Tick += (_, _) =>
                {
                    _fallbackTimer!.Stop();
                    if (!ServiceConnected && !EventPipeClient.IsServiceRunning()) StartLocalProtection(); // never run two protections at once
                };
                _fallbackTimer.Start();
            }
            RaiseStatus();
        });
    }

    private static void OnHostEvent(HostEvent e)
    {
        Run(() =>
        {
            RecentEvents.Insert(0, e);
            while (RecentEvents.Count > 100) RecentEvents.RemoveAt(RecentEvents.Count - 1);
            HostEventReceived?.Invoke(e);
            RaiseStatus();
        });
    }

    /// <summary>30 seconds after start, look for a new Kavach version (at most once a day).</summary>
    private static void StartAutomaticUpdateCheck()
    {
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        timer.Tick += async (_, _) =>
        {
            timer.Stop();
            var s = Context.Settings.Current;
            if (!s.AutoCheckAppUpdates) return;
            if (s.LastAppUpdateCheck is { } last && DateTime.Now - last < TimeSpan.FromHours(24)) return;

            var result = await AppUpdater.CheckAsync();
            if (result.Update == null) return;
            AvailableUpdate = result.Update;
            OnHostEvent(new HostEvent
            {
                Kind = HostEventKind.Status,
                Title = "Kavach update available",
                Message = $"Kavach v{result.Update.Version} is ready. Open About Kavach to install it.",
                Level = ThreatLevel.None
            });
        };
        timer.Start();
    }

    public static string ProtectionHostDescription =>
        ServiceConnected ? "Kavach Windows service (always on, even when this window is closed)"
        : LocalHost != null ? "This app (install the Kavach service for always-on protection)"
        : "Not running";

    // ───────── Scans ─────────

    /// <summary>Starts a scan unless one is already running. Returns the running job.</summary>
    public static ScanJob StartScan(ScanType type, string[]? paths = null, bool useCache = true)
    {
        if (ActiveScan != null && ActiveScan.IsRunning) return ActiveScan;

        var job = new ScanJob(Context, type, paths) { UseCache = useCache };
        ActiveScan = job;
        ActiveScanChanged?.Invoke();

        _ = job.RunAsync().ContinueWith(_ => Run(() =>
        {
            ActiveScanChanged?.Invoke();
            RaiseStatus();
        }), TaskScheduler.Default);
        return job;
    }

    public static void ClearFinishedScan()
    {
        if (ActiveScan != null && !ActiveScan.IsRunning)
        {
            ActiveScan = null;
            ActiveScanChanged?.Invoke();
        }
    }

    // ───────── Status ─────────

    public static ProtectionStatus GetStatus()
    {
        var s = Context.Settings.Current;
        if (!s.RealTimeProtection)
            return new ProtectionStatus(ProtectionLevel.AtRisk, "Your PC is at risk", "Real-time protection is turned off.");

        var lastScan = Context.History.All().FirstOrDefault(h => h.Type != ScanType.RealTime && h.Status == ScanStatus.Completed);
        if (lastScan != null && lastScan.ThreatsFound > 0 &&
            lastScan.Detections.Any(d => d.ActionTaken == "None" && System.IO.File.Exists(d.FilePath) && d.Level >= ThreatLevel.Medium))
        {
            return new ProtectionStatus(ProtectionLevel.AtRisk, "Threats need your attention",
                $"The last scan found {lastScan.ThreatsFound} threat(s) that are still on your PC.");
        }

        var lastQuickOrFull = new[] { s.LastQuickScan, s.LastFullScan }.Where(d => d.HasValue).Select(d => d!.Value).DefaultIfEmpty().Max();
        if (lastQuickOrFull == default)
            return new ProtectionStatus(ProtectionLevel.Attention, "Run your first scan", "Kavach has not scanned this PC yet. A Quick scan takes a few minutes.");
        if (DateTime.Now - lastQuickOrFull > TimeSpan.FromDays(7))
            return new ProtectionStatus(ProtectionLevel.Attention, "Time for a scan", $"Your last scan was {Ui.TimeAgo(lastQuickOrFull)}.");

        if (Context.Hashes.VersionInfo.Updated < DateTime.Now.AddDays(-14))
            return new ProtectionStatus(ProtectionLevel.Attention, "Signatures are getting old", "Update signatures to detect the newest threats.");

        return new ProtectionStatus(ProtectionLevel.Protected, "You're protected", "Real-time protection is on and your last scan was clean.");
    }

    public static void RaiseStatus() => Run(() => StatusChanged?.Invoke());

    public static void Toast(string message, bool isError = false) => Run(() => ToastRequested?.Invoke(message, isError));

    public static void Run(Action action)
    {
        var d = _dispatcher ?? Application.Current?.Dispatcher;
        if (d == null || d.CheckAccess()) action();
        else d.BeginInvoke(action);
    }

    public static void Shutdown()
    {
        ActiveScan?.Cancel();
        StopLocalProtection();
        ServiceClient?.Dispose();
        Context?.Cache.Save();
    }
}
