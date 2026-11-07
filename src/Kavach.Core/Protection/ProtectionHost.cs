using Kavach.Core.Infrastructure;

namespace Kavach.Core.Protection;

/// <summary>
/// Runs all background protection: real-time file monitor, ransomware guard, USB monitor,
/// scheduler and self-protection. Hosted by the Kavach Windows Service, or by the app itself
/// when the service is not installed.
/// </summary>
public sealed class ProtectionHost : IDisposable
{
    private readonly KavachContext _ctx;
    private readonly bool _isService;
    private FileSystemWatcher? _settingsWatcher;
    private FileSystemWatcher? _signaturesWatcher;
    private Timer? _reloadTimer;
    private Timer? _signatureTimer;
    private Timer? _autoUpdateTimer;
    private int _updating;
    private readonly object _applyLock = new();
    private string _folderKey = "";

    public ProtectionHost(KavachContext ctx, bool isService)
    {
        _ctx = ctx;
        _isService = isService;
        RealTime = new RealTimeMonitor(ctx, Raise);
        Ransomware = new RansomwareGuard(ctx, Raise);
        Usb = new UsbMonitor(ctx, Raise, RealTime);
        Scheduler = new Scheduler(ctx, Raise);
        ScriptMemory = new ScriptMemoryMonitor(ctx, Raise);
        RealTime.IgnorePath = RansomwareGuard.IsBaitFile;
    }

    public RealTimeMonitor RealTime { get; }
    public RansomwareGuard Ransomware { get; }
    public UsbMonitor Usb { get; }
    public Scheduler Scheduler { get; }
    public ScriptMemoryMonitor ScriptMemory { get; }
    public bool IsService => _isService;

    public event Action<HostEvent>? EventRaised;

    public void Start()
    {
        ApplySettings();
        Scheduler.Start();
        _ctx.Settings.Changed += _ => ApplySettings();

        if (_isService)
        {
            WatchSharedFiles();
            if (_ctx.Settings.Current.SelfProtection) SelfProtection.Apply(_ctx.Log);

            // Check for new online rules 2 minutes after start, then every 6 hours (downloads at most once a day)
            _autoUpdateTimer = new Timer(_ => AutoUpdateRules(), null, TimeSpan.FromMinutes(2), TimeSpan.FromHours(6));
        }

        _ctx.Log.Info("Protection", _isService ? "Protection started by the Kavach service" : "Protection started inside the Kavach app");
    }

    /// <summary>Turn each feature on or off to match the settings.</summary>
    public void ApplySettings()
    {
        lock (_applyLock)
        {
            var s = _ctx.Settings.Current;

            var folderKey = string.Join("|", s.ExtraMonitoredFolders);
            if (s.RealTimeProtection)
            {
                if (RealTime.IsRunning && folderKey != _folderKey) RealTime.Stop(); // folder list changed: rebuild watchers
                RealTime.Start();
            }
            else
            {
                RealTime.Stop();
            }
            _folderKey = folderKey;

            if (s.RealTimeProtection && s.RansomwareProtection) Ransomware.Start();
            else if (Ransomware.IsRunning)
            {
                Ransomware.Stop();
                if (!s.RansomwareProtection) Ransomware.RemoveBaitFiles();
            }

            if (s.RealTimeProtection && s.ScriptMemoryProtection) ScriptMemory.Start();
            else ScriptMemory.Stop();

            if (s.RealTimeProtection || s.UsbAutoScan) Usb.Start();
            else Usb.Stop();
        }
    }

    /// <summary>The service watches settings.json and the Signatures folder for changes made by the app.</summary>
    private void WatchSharedFiles()
    {
        try
        {
            _settingsWatcher = new FileSystemWatcher(AppPaths.DataDir, "settings.json")
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName
            };
            FileSystemEventHandler onSettings = (_, _) =>
            {
                _reloadTimer?.Dispose();
                _reloadTimer = new Timer(_ => _ctx.Settings.Reload(), null, 800, Timeout.Infinite);
            };
            _settingsWatcher.Changed += onSettings;
            _settingsWatcher.Created += onSettings;
            _settingsWatcher.Renamed += (s, e) => onSettings(s, e);
            _settingsWatcher.EnableRaisingEvents = true;

            _signaturesWatcher = new FileSystemWatcher(AppPaths.SignaturesDir)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName
            };
            FileSystemEventHandler onSignatures = (_, _) =>
            {
                _signatureTimer?.Dispose();
                _signatureTimer = new Timer(_ =>
                {
                    _ctx.ReloadSignatures();
                    _ctx.Log.Info("Signatures", $"Service reloaded signatures ({_ctx.Hashes.Count:N0} hashes, {_ctx.Rules.Rules.Count} rules)");
                }, null, 3000, Timeout.Infinite);
            };
            _signaturesWatcher.Changed += onSignatures;
            _signaturesWatcher.Created += onSignatures;
            _signaturesWatcher.Deleted += onSignatures;
            _signaturesWatcher.Renamed += (s, e) => onSignatures(s, e);
            _signaturesWatcher.EnableRaisingEvents = true;
        }
        catch (Exception ex)
        {
            _ctx.Log.Warning("Protection", "Cannot watch shared files: " + ex.Message);
        }
    }

    private async void AutoUpdateRules()
    {
        if (Interlocked.Exchange(ref _updating, 1) == 1) return;
        try
        {
            var s = _ctx.Settings.Current;
            if (!s.AutoUpdateRules) return;
            if (s.LastOnlineRulesUpdate is { } last && DateTime.Now - last < TimeSpan.FromHours(24)) return;

            var result = await new SignatureUpdater(_ctx).DownloadOnlineRulesAsync();
            if (!result.Success) _ctx.Log.Warning("Updates", "Automatic rule update: " + result.Message);
        }
        catch (Exception ex)
        {
            _ctx.Log.Warning("Updates", "Automatic rule update failed: " + ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _updating, 0);
        }
    }

    private void Raise(HostEvent e)
    {
        try
        {
            EventRaised?.Invoke(e);
        }
        catch (Exception ex)
        {
            _ctx.Log.Error("Protection", "Event handler failed: " + ex.Message);
        }
    }

    public void Stop()
    {
        Scheduler.Stop();
        Usb.Stop();
        ScriptMemory.Stop();
        Ransomware.Stop();
        RealTime.Stop();
        _settingsWatcher?.Dispose();
        _signaturesWatcher?.Dispose();
        _reloadTimer?.Dispose();
        _signatureTimer?.Dispose();
        _autoUpdateTimer?.Dispose();
    }

    public void Dispose() => Stop();
}
