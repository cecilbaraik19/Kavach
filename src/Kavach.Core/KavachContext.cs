using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;
using Kavach.Core.Response;

namespace Kavach.Core;

/// <summary>
/// One object that holds every shared part of Kavach: settings, log, history,
/// signatures, scan engine and quarantine. Created once by the app or by the service.
/// </summary>
public sealed class KavachContext
{
    private KavachContext()
    {
        AppPaths.EnsureDirectories();
        Settings = new SettingsManager();
        Log = new ActivityLog();
        History = new HistoryStore();
        Hashes = new HashDatabase();
        Rules = new RuleSet();
        Cache = new ScanCache();
        Engine = new ScanEngine(Settings, Hashes, Rules, Cache);
        Quarantine = new QuarantineManager(Log, Settings);
        ReloadSignatures();
    }

    public static KavachContext Create() => new();

    public SettingsManager Settings { get; }
    public ActivityLog Log { get; }
    public HistoryStore History { get; }
    public HashDatabase Hashes { get; }
    public RuleSet Rules { get; }
    public ScanCache Cache { get; }
    public ScanEngine Engine { get; }
    public QuarantineManager Quarantine { get; }

    public event Action? SignaturesReloaded;

    /// <summary>Load hash lists and rules again (after an update or import).</summary>
    public void ReloadSignatures()
    {
        Hashes.Load();
        Rules.Load();
        Cache.Load(Fingerprint);
        if (Rules.Errors.Count > 0)
        {
            Log.Warning("Signatures", $"{Rules.Errors.Count} rule(s) could not be loaded. First error: {Rules.Errors[0]}");
        }
        SignaturesReloaded?.Invoke();
    }

    /// <summary>Changes whenever signatures change, so the scan cache knows to start over.</summary>
    public string Fingerprint => $"{Hashes.Fingerprint}:{Rules.Rules.Count}";
}
