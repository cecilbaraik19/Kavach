using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Text;
using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;
using Kavach.Core.Native;
using Kavach.Core.Response;
using Microsoft.Win32;

namespace Kavach.Core.Protection;

/// <summary>
/// Script memory scanning ("fileless" attack protection).
///
/// Many attacks never save a file: they run PowerShell with an encoded command, or download
/// text and run it straight from memory. Windows PowerShell can record every piece of script it
/// runs (Script Block Logging, event 4104) — already decoded, after Base64 and most obfuscation
/// have been removed. Kavach reads those events live, checks each script with the same script
/// analyzer and YARA rules it uses for files, and stops the PowerShell process if it is malicious.
/// </summary>
public sealed class ScriptMemoryMonitor : IDisposable
{
    private static readonly string[] Channels =
    {
        "Microsoft-Windows-PowerShell/Operational", // Windows PowerShell 5.1
        "PowerShellCore/Operational"                // PowerShell 7
    };

    private readonly KavachContext _ctx;
    private readonly Action<HostEvent> _raise;
    private readonly List<EventLogWatcher> _watchers = new();

    // Long scripts are split over several events; parts are joined by ScriptBlockId
    private readonly ConcurrentDictionary<string, string[]> _parts = new();
    private readonly ConcurrentDictionary<string, DateTime> _seen = new();
    private readonly ConcurrentDictionary<int, DateTime> _lastAlertByProcess = new();

    public ScriptMemoryMonitor(KavachContext ctx, Action<HostEvent> raise)
    {
        _ctx = ctx;
        _raise = raise;
    }

    public bool IsRunning { get; private set; }

    public void Start()
    {
        if (IsRunning) return;
        EnableScriptBlockLogging();

        foreach (var channel in Channels)
        {
            try
            {
                var query = new EventLogQuery(channel, PathType.LogName, "*[System[(EventID=4104)]]");
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += OnEvent;
                watcher.Enabled = true;
                _watchers.Add(watcher);
            }
            catch (EventLogNotFoundException)
            {
                // PowerShell 7 is not installed — nothing to watch
            }
            catch (Exception ex)
            {
                _ctx.Log.Warning("ScriptMemory", $"Cannot watch {channel}: {ex.Message}");
            }
        }

        IsRunning = _watchers.Count > 0;
        if (IsRunning) _ctx.Log.Info("ScriptMemory", $"Script memory scanning started ({_watchers.Count} PowerShell log(s))");
    }

    public void Stop()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.Enabled = false;
                w.Dispose();
            }
            catch
            {
            }
        }
        _watchers.Clear();
        if (IsRunning) _ctx.Log.Warning("ScriptMemory", "Script memory scanning stopped");
        IsRunning = false;
    }

    /// <summary>Turns on PowerShell Script Block Logging (needs administrator rights, so done by the service).</summary>
    private void EnableScriptBlockLogging()
    {
        if (!AdminHelper.IsAdministrator() && !AdminHelper.IsLocalSystem()) return;
        foreach (var keyPath in new[]
                 {
                     @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                     @"SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging"
                 })
        {
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(keyPath, true);
                if (key.GetValue("EnableScriptBlockLogging") is int v && v == 1) continue;
                key.SetValue("EnableScriptBlockLogging", 1, RegistryValueKind.DWord);
                _ctx.Log.Info("ScriptMemory", "Turned on PowerShell script block logging (" + keyPath.Split('\\')[^2] + ")");
            }
            catch (Exception ex)
            {
                _ctx.Log.Warning("ScriptMemory", "Cannot turn on script block logging: " + ex.Message);
            }
        }
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            using var record = e.EventRecord;
            if (record == null || record.Properties.Count < 4) return;

            var number = Convert.ToInt32(record.Properties[0].Value);
            var total = Convert.ToInt32(record.Properties[1].Value);
            var text = record.Properties[2].Value as string ?? "";
            var blockId = record.Properties[3].Value?.ToString() ?? Guid.NewGuid().ToString();
            var scriptPath = record.Properties.Count > 4 ? record.Properties[4].Value as string : null;
            var pid = record.ProcessId ?? 0;

            if (total > 1)
            {
                var parts = _parts.GetOrAdd(blockId, _ => new string[Math.Min(total, 500)]);
                if (number >= 1 && number <= parts.Length) parts[number - 1] = text;
                if (parts.Any(p => p == null)) return; // wait for the remaining parts
                _parts.TryRemove(blockId, out _);
                text = string.Concat(parts);
            }

            if (!_seen.TryAdd(blockId, DateTime.UtcNow)) return;
            CleanUp();
            Check(text, scriptPath, pid);
        }
        catch (Exception ex)
        {
            _ctx.Log.Error("ScriptMemory", ex.Message);
        }
    }

    private void Check(string text, string? scriptPath, int pid)
    {
        if (text.Length < 20) return;
        if (pid == Environment.ProcessId) return;

        // PowerShell's own modules and signed scripts from trusted places are fine
        if (!string.IsNullOrEmpty(scriptPath))
        {
            if (FileClassifier.IsInWindowsFolder(scriptPath)) return;
            if (File.Exists(scriptPath) && SignatureVerifier.Check(scriptPath).IsTrusted) return;
        }

        var data = Encoding.UTF8.GetBytes(text);
        var sha = HashDatabase.ComputeSha256(data);
        if (_ctx.Settings.IsHashAllowed(sha)) return;

        var threatName = "";
        var level = ThreatLevel.None;
        var reasons = new List<string>();

        // 1) YARA rules
        foreach (var match in _ctx.Rules.Match(data, data.Length))
        {
            if (match.Rule.Level > level)
            {
                level = match.Rule.Level;
                threatName = match.Rule.ThreatName;
            }
            reasons.Add("Rule " + match.Rule.Name);
        }

        // 2) Script behaviour analyzer
        var verdict = ScriptAnalyzer.Analyze(data, ".ps1");
        var scriptLevel = ScriptAnalyzer.LevelFor(verdict, ".ps1");
        if (scriptLevel > level)
        {
            level = scriptLevel;
            threatName = "Trojan.PowerShell.Fileless";
        }
        reasons.AddRange(verdict.Reasons);

        if (level == ThreatLevel.None) return;

        // One alert per process every 10 seconds (a script can produce many blocks)
        var now = DateTime.UtcNow;
        if (_lastAlertByProcess.TryGetValue(pid, out var last) && now - last < TimeSpan.FromSeconds(10)) return;
        _lastAlertByProcess[pid] = now;

        var processPath = pid > 0 ? NativeMethods.GetProcessImagePath(pid) : null;
        var where = !string.IsNullOrEmpty(scriptPath) ? scriptPath : $"{Path.GetFileName(processPath ?? "PowerShell")} (in memory, process {pid})";

        var stop = level >= ThreatLevel.High && pid > 4 && _ctx.Settings.Current.AutoQuarantine;
        var stopped = stop && ProcessKiller.Kill(pid);

        var detection = new Detection
        {
            FilePath = where,
            ThreatName = threatName,
            Level = level,
            Source = DetectionSource.ScriptMemory,
            ProcessId = pid,
            Sha256 = sha,
            Details = "Script run from memory: " + string.Join(", ", reasons.Distinct().Take(6)),
            ActionTaken = stopped ? "PowerShell stopped" : "Reported"
        };

        _ctx.Log.Threat("ScriptMemory", $"{threatName} in {where}: {detection.Details}" + (stopped ? " — process stopped" : ""));
        _ctx.History.Add(new ScanSummary
        {
            Type = ScanType.RealTime,
            Status = ScanStatus.Completed,
            Finished = DateTime.Now,
            FilesScanned = 1,
            ThreatsFound = 1,
            Targets = { where },
            Detections = { detection }
        });

        _raise(new HostEvent
        {
            Kind = HostEventKind.ThreatDetected,
            Title = stopped ? "Fileless attack stopped" : "Suspicious script running",
            Message = stopped
                ? $"A PowerShell script running from memory looked like {threatName}. Kavach stopped it."
                : $"A PowerShell script running from memory looks suspicious ({threatName}).",
            Level = level,
            Detection = detection
        });
    }

    private void CleanUp()
    {
        if (_seen.Count < 5000) return;
        var cutoff = DateTime.UtcNow.AddMinutes(-10);
        foreach (var kv in _seen)
            if (kv.Value < cutoff) _seen.TryRemove(kv.Key, out _);
        if (_parts.Count > 200) _parts.Clear();
        if (_lastAlertByProcess.Count > 500) _lastAlertByProcess.Clear();
    }

    public void Dispose() => Stop();
}
