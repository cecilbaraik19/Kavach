using System.Security.Cryptography;

namespace Kavach.Core.Infrastructure;

public enum PerformanceMode
{
    /// <summary>One worker thread, low priority, small pause between files.</summary>
    Low,
    /// <summary>Half the CPU cores.</summary>
    Balanced,
    /// <summary>All CPU cores.</summary>
    Fast
}

public enum ScheduleFrequency
{
    Daily,
    Weekly
}

/// <summary>An automatic scan that runs at a set time.</summary>
public sealed class ScheduleEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Weekly safety check";
    public ScanType ScanType { get; set; } = ScanType.Quick;
    public ScheduleFrequency Frequency { get; set; } = ScheduleFrequency.Weekly;
    public DayOfWeek Day { get; set; } = DayOfWeek.Monday;
    /// <summary>Time of day in 24-hour "HH:mm" format.</summary>
    public string Time { get; set; } = "09:00";
    public bool Enabled { get; set; } = true;
    public bool SkipOnBattery { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime? LastRun { get; set; }

    public TimeSpan TimeOfDay =>
        TimeSpan.TryParse(Time, out var t) ? t : new TimeSpan(9, 0, 0);

    /// <summary>The next time this schedule should run.</summary>
    public DateTime NextRun(DateTime now)
    {
        var from = LastRun.HasValue && LastRun.Value > CreatedAt ? LastRun.Value : CreatedAt;
        if (from > now) from = now;

        var candidate = from.Date + TimeOfDay;
        if (candidate <= from) candidate = candidate.AddDays(1);

        if (Frequency == ScheduleFrequency.Weekly)
        {
            while (candidate.DayOfWeek != Day) candidate = candidate.AddDays(1);
        }
        return candidate;
    }

    public string Describe() =>
        Frequency == ScheduleFrequency.Daily
            ? $"Every day at {Time}"
            : $"Every {Day} at {Time}";
}

/// <summary>Every user setting. Saved to C:\ProgramData\Kavach\settings.json.</summary>
public sealed class KavachSettings
{
    // Real-time protection
    public bool RealTimeProtection { get; set; } = true;
    public bool DownloadWarnings { get; set; } = true;
    public bool UsbAutoScan { get; set; } = true;
    public bool RansomwareProtection { get; set; } = true;
    public bool ScriptMemoryProtection { get; set; } = true;

    // Signature updates
    public bool AutoUpdateRules { get; set; } = true;
    public DateTime? LastOnlineRulesUpdate { get; set; }

    // Kavach updating itself (GitHub Releases of this repository)
    public string UpdateRepository { get; set; } = "cecilbaraik19/Kavach";
    public bool AutoCheckAppUpdates { get; set; } = true;
    public DateTime? LastAppUpdateCheck { get; set; }
    public bool SelfProtection { get; set; } = true;
    public bool AutoQuarantine { get; set; } = true;
    public List<string> ExtraMonitoredFolders { get; set; } = new();

    // Scanning
    public bool ScanArchives { get; set; } = true;
    public int MaxArchiveDepth { get; set; } = 2;
    public int MaxFileSizeMb { get; set; } = 100;
    public bool SkipMediaFiles { get; set; } = true;
    public bool UseScanCache { get; set; } = true;
    public PerformanceMode Performance { get; set; } = PerformanceMode.Balanced;
    public bool PauseOnBattery { get; set; } = true;
    public bool PauseWhenFullscreen { get; set; } = true;

    // Allowlist (exclusions)
    public List<string> ExcludedPaths { get; set; } = new();
    public List<string> AllowedHashes { get; set; } = new();

    // Schedules
    public List<ScheduleEntry> Schedules { get; set; } = new()
    {
        new ScheduleEntry()
    };

    // Online services
    public string? VirusTotalApiKey { get; set; }
    public string? AbuseChAuthKey { get; set; }

    // Integration
    public bool ContextMenuEnabled { get; set; }
    public bool StartWithWindows { get; set; } = true;
    public bool MinimizeToTray { get; set; } = true;
    public string Theme { get; set; } = "Dark";

    // Settings password (PBKDF2 hash, never the password itself)
    public string? PasswordHash { get; set; }
    public string? PasswordSalt { get; set; }

    // Dashboard info
    public DateTime? LastQuickScan { get; set; }
    public DateTime? LastFullScan { get; set; }
    public int ThreatsBlockedTotal { get; set; }

    public bool HasPassword => !string.IsNullOrEmpty(PasswordHash);

    public void SetPassword(string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            PasswordHash = null;
            PasswordSalt = null;
            return;
        }
        var salt = RandomNumberGenerator.GetBytes(16);
        PasswordSalt = Convert.ToBase64String(salt);
        PasswordHash = Convert.ToBase64String(Hash(password, salt));
    }

    public bool CheckPassword(string password)
    {
        if (!HasPassword) return true;
        try
        {
            var salt = Convert.FromBase64String(PasswordSalt!);
            var expected = Convert.FromBase64String(PasswordHash!);
            return CryptographicOperations.FixedTimeEquals(expected, Hash(password, salt));
        }
        catch
        {
            return false;
        }
    }

    private static byte[] Hash(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
}

/// <summary>Loads, saves and shares the settings. Raises <see cref="Changed"/> after every save.</summary>
public sealed class SettingsManager
{
    private readonly object _lock = new();
    private KavachSettings _current;

    public SettingsManager()
    {
        _current = JsonStore.Load(AppPaths.SettingsFile, () => new KavachSettings());
    }

    public event Action<KavachSettings>? Changed;

    public KavachSettings Current
    {
        get { lock (_lock) return _current; }
    }

    /// <summary>Change settings safely: Update(s => s.RealTimeProtection = false).</summary>
    public void Update(Action<KavachSettings> change)
    {
        KavachSettings snapshot;
        lock (_lock)
        {
            change(_current);
            JsonStore.Save(AppPaths.SettingsFile, _current);
            snapshot = _current;
        }
        Changed?.Invoke(snapshot);
    }

    /// <summary>Re-read the file (used when the other process changed it).</summary>
    public void Reload()
    {
        KavachSettings snapshot;
        lock (_lock)
        {
            _current = JsonStore.Load(AppPaths.SettingsFile, () => new KavachSettings());
            snapshot = _current;
        }
        Changed?.Invoke(snapshot);
    }

    public bool IsExcluded(string path)
    {
        var s = Current;
        foreach (var excluded in s.ExcludedPaths)
        {
            if (string.IsNullOrWhiteSpace(excluded)) continue;
            if (string.Equals(path, excluded, StringComparison.OrdinalIgnoreCase)) return true;
            if (Directory.Exists(excluded) && AppPaths.IsUnder(path, excluded)) return true;
        }
        return false;
    }

    public bool IsHashAllowed(string? sha256)
    {
        if (string.IsNullOrEmpty(sha256)) return false;
        return Current.AllowedHashes.Any(h => string.Equals(h, sha256, StringComparison.OrdinalIgnoreCase));
    }
}
