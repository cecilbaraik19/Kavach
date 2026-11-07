using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using Kavach.Core;
using Kavach.Core.Infrastructure;
using Kavach.Core.SystemChecks;

namespace Kavach.App.Pages;

/// <summary>Base class that tells the screen when a value changes.</summary>
public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    protected void Notify([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>One threat in a list of scan results.</summary>
public sealed class DetectionRow : Observable
{
    private bool _isSelected = true;
    private string _action;

    public DetectionRow(Detection detection)
    {
        D = detection;
        _action = detection.ActionTaken;
    }

    public Detection D { get; }
    public ThreatLevel Level => D.Level;
    public string LevelText => D.Level.ToString().ToUpperInvariant();
    public string ThreatName => D.ThreatName;
    public string FileName => string.IsNullOrEmpty(D.InnerPath) ? Path.GetFileName(D.FilePath) : Path.GetFileName(D.InnerPath);
    public string Location => D.DisplayPath;
    public string Details => D.Details;
    public string SourceText => D.Source switch
    {
        DetectionSource.Hash => "Known malware hash",
        DetectionSource.Rule => "Detection rule",
        DetectionSource.Heuristic => "Heuristics",
        DetectionSource.Script => "Script analysis",
        DetectionSource.ScriptMemory => "Script memory scan",
        DetectionSource.FakeSystemFile => "Fake system file",
        DetectionSource.FileName => "File name trick",
        DetectionSource.Archive => "Archive check",
        DetectionSource.Ransomware => "Ransomware guard",
        DetectionSource.Startup => "Startup check",
        DetectionSource.Hosts => "Hosts file",
        DetectionSource.Process => "Running program",
        DetectionSource.Network => "Network",
        DetectionSource.Usb => "USB",
        _ => D.Source.ToString()
    };
    public bool IsRunning => D.ProcessId.HasValue;
    public bool CanQuarantine => D.Source != DetectionSource.Hosts && File.Exists(D.FilePath);

    public bool IsSelected
    {
        get => _isSelected;
        set => Set(ref _isSelected, value);
    }

    public string Action
    {
        get => _action;
        set
        {
            Set(ref _action, value);
            D.ActionTaken = value;
            Notify(nameof(IsHandled));
        }
    }

    public bool IsHandled => _action != "None";
}

public sealed class QuarantineRow
{
    public QuarantineRow(QuarantineItem item) { Item = item; }
    public QuarantineItem Item { get; }
    public ThreatLevel Level => Item.Level;
    public string LevelText => Item.Level.ToString().ToUpperInvariant();
    public string ThreatName => Item.ThreatName;
    public string FileName => Path.GetFileName(Item.OriginalPath);
    public string OriginalPath => Item.OriginalPath;
    public string SizeText => Ui.FormatBytes(Item.Size);
    public string DateText => Item.QuarantinedAt.ToString("dd MMM yyyy, hh:mm tt");
    public string ShortHash => Item.Sha256.Length > 16 ? Item.Sha256[..16] + "…" : Item.Sha256;
}

public sealed class StartupRow
{
    public StartupRow(StartupItem item) { Item = item; }
    public StartupItem Item { get; }
    public ThreatLevel Level => Item.Risk;
    public string LevelText => Item.Risk switch
    {
        ThreatLevel.None => "OK",
        ThreatLevel.Low => "NOTE",
        _ => Item.Risk.ToString().ToUpperInvariant()
    };
    public string Name => Item.Name;
    public string SourceText => Item.SourceText;
    public string Command => Item.Command;
    public string Reason => Item.Reason;
    public bool CanDisable => Item.CanDisable && Item.Source != StartupSource.Service;
}

public sealed class DisabledRow
{
    public DisabledRow(DisabledStartupEntry entry) { Entry = entry; }
    public DisabledStartupEntry Entry { get; }
    public string Name => Entry.Name;
    public string Detail => $"{Entry.Source} • disabled {Entry.DisabledAt:dd MMM yyyy}";
    public string Command => Entry.Command;
}

public sealed class HistoryRow
{
    public HistoryRow(ScanSummary scan) { Scan = scan; }
    public ScanSummary Scan { get; }
    public string Title => Ui.ScanTypeName(Scan.Type);
    public string When => Scan.Started.ToString("dd MMM yyyy, hh:mm tt");
    public string Result => Scan.Status switch
    {
        ScanStatus.Cancelled => "Cancelled",
        ScanStatus.Failed => "Failed",
        _ => Scan.ThreatsFound == 0 ? "Clean" : $"{Scan.ThreatsFound} threat(s)"
    };
    public ThreatLevel Level => Scan.ThreatsFound > 0 ? ThreatLevel.High : Scan.Status == ScanStatus.Completed ? ThreatLevel.None : ThreatLevel.Medium;
    public string Numbers => $"{Scan.FilesScanned:N0} scanned • {Ui.Duration(Scan.Duration)}";
}

public sealed class LogRow
{
    public LogRow(LogEntry entry) { Entry = entry; }
    public LogEntry Entry { get; }
    public string Time => Entry.Time.ToString("dd MMM, HH:mm:ss");
    public string Category => Entry.Category;
    public string Message => Entry.Message;
    public string LevelText => Entry.Level.ToString().ToUpperInvariant();
    public ThreatLevel Level => Entry.Level switch
    {
        LogLevel.Threat => ThreatLevel.High,
        LogLevel.Error => ThreatLevel.Critical,
        LogLevel.Warning => ThreatLevel.Medium,
        _ => ThreatLevel.Low
    };
}

public sealed class ScheduleRow
{
    public ScheduleRow(ScheduleEntry entry) { Entry = entry; }
    public ScheduleEntry Entry { get; }
    public string Name => Entry.Name;
    public string Describe => Entry.Describe() + (Entry.SkipOnBattery ? " • waits for power" : "");
    public string TypeText => Entry.ScanType == ScanType.Full ? "Full scan" : "Quick scan";
    public string NextText => Entry.Enabled ? "Next: " + Entry.NextRun(DateTime.Now).ToString("ddd dd MMM, HH:mm") : "Paused";
    public string LastText => Entry.LastRun.HasValue ? "Last run " + Ui.TimeAgo(Entry.LastRun) : "Never run";
    public bool Enabled => Entry.Enabled;
}

public sealed class EventRow
{
    public EventRow(HostEvent e) { E = e; }
    public HostEvent E { get; }
    public string Title => E.Title;
    public string Message => E.Message;
    public string Time => E.Time.ToString("HH:mm:ss");
    public ThreatLevel Level => E.Level;
}
