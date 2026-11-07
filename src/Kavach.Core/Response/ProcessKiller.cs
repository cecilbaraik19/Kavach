using System.Diagnostics;
using Kavach.Core.Native;

namespace Kavach.Core.Response;

/// <summary>Stops malicious programs that are already running.</summary>
public static class ProcessKiller
{
    /// <summary>Process IDs of every running copy of a program file.</summary>
    public static List<int> FindByPath(string path)
    {
        var result = new List<int>();
        var full = SafeFullPath(path);
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id == Environment.ProcessId || process.Id <= 4) continue;
                var image = NativeMethods.GetProcessImagePath(process.Id);
                if (image != null && string.Equals(SafeFullPath(image), full, StringComparison.OrdinalIgnoreCase))
                    result.Add(process.Id);
            }
            catch
            {
                // process ended while we looked at it
            }
            finally
            {
                process.Dispose();
            }
        }
        return result;
    }

    /// <summary>Kills every process running from <paramref name="path"/>. Returns how many were stopped.</summary>
    public static int KillByPath(string path)
    {
        var killed = 0;
        foreach (var pid in FindByPath(path))
        {
            if (Kill(pid)) killed++;
        }
        if (killed > 0) Thread.Sleep(300); // give Windows a moment to release the file
        return killed;
    }

    public static bool Kill(int processId)
    {
        if (processId == Environment.ProcessId || processId <= 4) return false;
        try
        {
            using var process = Process.GetProcessById(processId);
            process.Kill(entireProcessTree: true);
            process.WaitForExit(3000);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string SafeFullPath(string p)
    {
        try { return Path.GetFullPath(p); } catch { return p; }
    }
}
