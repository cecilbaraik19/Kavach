using System.Diagnostics;
using Kavach.Core.Engine;
using Kavach.Core.Native;

namespace Kavach.Core.SystemChecks;

/// <summary>A running program, as shown in the scan results.</summary>
public sealed record RunningProgram(int ProcessId, string Name, string? Path);

/// <summary>Scans the program file behind every running process.</summary>
public static class ProcessScanner
{
    public static List<RunningProgram> ListRunning()
    {
        var list = new List<RunningProgram>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id <= 4) continue;
                list.Add(new RunningProgram(process.Id, process.ProcessName, NativeMethods.GetProcessImagePath(process.Id)));
            }
            catch
            {
                // ended or protected
            }
            finally
            {
                process.Dispose();
            }
        }
        return list;
    }

    public static List<Detection> ScanRunning(ScanEngine engine, CancellationToken token, Action<string>? onFile = null)
    {
        var detections = new List<Detection>();
        var byPath = ListRunning()
            .Where(p => !string.IsNullOrEmpty(p.Path))
            .GroupBy(p => p.Path!, StringComparer.OrdinalIgnoreCase);

        foreach (var group in byPath)
        {
            token.ThrowIfCancellationRequested();
            var path = group.Key;
            onFile?.Invoke(path);

            var firstPid = group.First().ProcessId;
            var verdict = engine.ScanFile(path, ScanFileOptions.Default, token);
            foreach (var d in verdict.Detections)
            {
                d.ProcessId = firstPid;
                d.Details = $"Running now (PID {string.Join(", ", group.Select(g => g.ProcessId))}). " + d.Details;
                detections.Add(d);
            }

            // A program running from the Temp folder without a signature is a strong warning sign
            if (!verdict.IsThreat && IsInTemp(path))
            {
                var sig = SignatureVerifier.Check(path);
                if (sig.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid)
                {
                    detections.Add(new Detection
                    {
                        FilePath = path,
                        ThreatName = "Suspicious.RunningFromTemp",
                        Level = ThreatLevel.Medium,
                        Source = DetectionSource.Process,
                        ProcessId = firstPid,
                        Sha256 = verdict.Sha256,
                        Details = $"Unsigned program running from a temporary folder (PID {firstPid})"
                    });
                }
            }
        }
        return detections;
    }

    private static bool IsInTemp(string path) =>
        path.StartsWith(System.IO.Path.GetTempPath(), StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase)
        || path.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase);
}
