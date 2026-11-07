namespace Kavach.Core;

/// <summary>How dangerous a detection is.</summary>
public enum ThreatLevel
{
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>Which detection method found the threat.</summary>
public enum DetectionSource
{
    Hash,
    Rule,
    Heuristic,
    Script,
    FakeSystemFile,
    FileName,
    Archive,
    Ransomware,
    Startup,
    Hosts,
    Process,
    Network,
    Usb,
    ScriptMemory
}

public enum ScanType
{
    Quick,
    Full,
    Custom,
    Processes,
    System,
    RealTime,
    Usb,
    Scheduled
}

public enum ScanStatus
{
    Running,
    Completed,
    Cancelled,
    Failed
}

/// <summary>One threat found on the computer.</summary>
public sealed class Detection
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string FilePath { get; set; } = "";
    /// <summary>When the threat is inside an archive, the path of the file inside it.</summary>
    public string? InnerPath { get; set; }
    public string ThreatName { get; set; } = "";
    public ThreatLevel Level { get; set; }
    public DetectionSource Source { get; set; }
    public string Details { get; set; } = "";
    public string? Sha256 { get; set; }
    public int? ProcessId { get; set; }
    public DateTime FoundAt { get; set; } = DateTime.Now;
    public string ActionTaken { get; set; } = "None";

    public string DisplayPath => string.IsNullOrEmpty(InnerPath) ? FilePath : $"{FilePath}  ›  {InnerPath}";
}

/// <summary>Result of scanning a single file.</summary>
public sealed class FileVerdict
{
    public FileVerdict(string path) { Path = path; }

    public string Path { get; }
    public List<Detection> Detections { get; } = new();
    public bool Skipped { get; set; }
    public string? SkipReason { get; set; }
    public bool FromCache { get; set; }
    public string? Sha256 { get; set; }

    public bool IsThreat => Detections.Count > 0;

    public ThreatLevel MaxLevel => Detections.Count == 0 ? ThreatLevel.None : Detections.Max(d => d.Level);

    /// <summary>The most serious detection, used as the main name.</summary>
    public Detection? Primary => Detections.OrderByDescending(d => d.Level).FirstOrDefault();
}

/// <summary>Live numbers shown while a scan runs.</summary>
public sealed record ScanProgress(
    int FilesScanned,
    int FilesSkipped,
    int ThreatsFound,
    int FilesDiscovered,
    bool DiscoveryFinished,
    string CurrentFile,
    TimeSpan Elapsed)
{
    public double? Percent =>
        DiscoveryFinished && FilesDiscovered > 0
            ? Math.Min(100.0, (FilesScanned + FilesSkipped) * 100.0 / FilesDiscovered)
            : null;
}

/// <summary>Saved record of one finished scan (shown on the History page).</summary>
public sealed class ScanSummary
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public ScanType Type { get; set; }
    public ScanStatus Status { get; set; } = ScanStatus.Running;
    public DateTime Started { get; set; } = DateTime.Now;
    public DateTime? Finished { get; set; }
    public int FilesScanned { get; set; }
    public int FilesSkipped { get; set; }
    public int ThreatsFound { get; set; }
    public List<string> Targets { get; set; } = new();
    public List<Detection> Detections { get; set; } = new();
    public string? Error { get; set; }

    public TimeSpan Duration => (Finished ?? DateTime.Now) - Started;
}

/// <summary>A file kept safely inside the quarantine vault.</summary>
public sealed class QuarantineItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string OriginalPath { get; set; } = "";
    public string StoredFileName { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string ThreatName { get; set; } = "";
    public ThreatLevel Level { get; set; }
    public long Size { get; set; }
    public DateTime QuarantinedAt { get; set; } = DateTime.Now;
}

public enum LogLevel
{
    Info,
    Warning,
    Threat,
    Error
}

/// <summary>One line in the activity log.</summary>
public sealed class LogEntry
{
    public DateTime Time { get; set; } = DateTime.Now;
    public LogLevel Level { get; set; }
    public string Category { get; set; } = "";
    public string Message { get; set; } = "";
}

public enum HostEventKind
{
    ThreatDetected,
    ThreatQuarantined,
    DownloadWarning,
    UsbInserted,
    RansomwareBlocked,
    ScheduledScanStarted,
    ScheduledScanFinished,
    Status,
    Error
}

/// <summary>Message from the protection engine to the user interface (also sent over the named pipe).</summary>
public sealed class HostEvent
{
    public HostEventKind Kind { get; set; }
    public string Title { get; set; } = "";
    public string Message { get; set; } = "";
    public ThreatLevel Level { get; set; }
    public Detection? Detection { get; set; }
    public DateTime Time { get; set; } = DateTime.Now;
}
