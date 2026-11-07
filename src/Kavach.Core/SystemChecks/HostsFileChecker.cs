using System.Net;
using Kavach.Core.Infrastructure;

namespace Kavach.Core.SystemChecks;

public sealed class HostsEntry
{
    public string Ip { get; set; } = "";
    public string Host { get; set; } = "";
    public int LineNumber { get; set; }
    public ThreatLevel Risk { get; set; }
    public string? Reason { get; set; }
}

public sealed class HostsCheckResult
{
    public string Path { get; set; } = "";
    public bool Exists { get; set; }
    public List<HostsEntry> Entries { get; } = new();
    public List<Detection> Detections { get; } = new();
    public bool IsClean => Detections.Count == 0;
}

/// <summary>
/// The hosts file can redirect website names to other addresses.
/// Malware edits it to send you to fake banking sites or to block antivirus updates.
/// </summary>
public static class HostsFileChecker
{
    public static string HostsPath =>
        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    /// <summary>Sites that should never be redirected.</summary>
    private static readonly string[] SensitiveDomains =
    {
        "microsoft.com", "windowsupdate.com", "windows.com", "live.com", "office.com", "google.com", "gmail.com",
        "youtube.com", "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com", "amazon.", "paypal.",
        "apple.com", "icloud.com", "github.com", "linkedin.com", "netflix.com", "sbi.co.in", "onlinesbi", "hdfcbank",
        "icicibank", "axisbank", "paytm", "phonepe", "npci.org.in"
    };

    /// <summary>Security sites malware likes to block so you cannot get help.</summary>
    private static readonly string[] SecurityDomains =
    {
        "virustotal.com", "malwarebytes.", "kaspersky.", "avast.", "avg.com", "eset.", "bitdefender.", "norton",
        "mcafee.", "sophos.", "trendmicro.", "f-secure.", "quickheal.", "abuse.ch", "update.microsoft.com",
        "definitionupdates.microsoft.com", "wdcp.microsoft.com", "go.microsoft.com"
    };

    public static HostsCheckResult Check()
    {
        var result = new HostsCheckResult { Path = HostsPath, Exists = File.Exists(HostsPath) };
        if (!result.Exists) return result;

        string[] lines;
        try
        {
            lines = File.ReadAllLines(HostsPath);
        }
        catch
        {
            return result;
        }

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var ip = parts[0];
            foreach (var host in parts.Skip(1))
            {
                var entry = new HostsEntry { Ip = ip, Host = host, LineNumber = i + 1 };
                Evaluate(entry);
                result.Entries.Add(entry);

                if (entry.Risk > ThreatLevel.Low)
                {
                    result.Detections.Add(new Detection
                    {
                        FilePath = HostsPath,
                        ThreatName = entry.Risk >= ThreatLevel.High ? "Hijack.Hosts.Redirect" : "Hijack.Hosts.BlockSecurity",
                        Level = entry.Risk,
                        Source = DetectionSource.Hosts,
                        Details = $"Line {entry.LineNumber}: {host} → {ip}. {entry.Reason}"
                    });
                }
            }
        }
        return result;
    }

    private static void Evaluate(HostsEntry entry)
    {
        var host = entry.Host.ToLowerInvariant();
        var isLocal = entry.Ip is "127.0.0.1" or "0.0.0.0" or "::1" or "::" ||
                      (IPAddress.TryParse(entry.Ip, out var addr) && IPAddress.IsLoopback(addr));

        bool Matches(string[] list) => list.Any(d => host == d || host.EndsWith("." + d) || (d.EndsWith('.') && host.Contains(d)) || host.Contains(d) && d.Length > 6);

        if (Matches(SecurityDomains))
        {
            entry.Risk = isLocal ? ThreatLevel.Medium : ThreatLevel.High;
            entry.Reason = isLocal ? "A security website is blocked" : "A security website is redirected to another server";
            return;
        }

        if (Matches(SensitiveDomains) && !isLocal)
        {
            entry.Risk = ThreatLevel.High;
            entry.Reason = "A popular or banking website is redirected to another server (possible phishing)";
            return;
        }

        if (host == "localhost" || isLocal)
        {
            entry.Risk = ThreatLevel.None; // normal ad-blocking or developer entries
            return;
        }

        entry.Risk = ThreatLevel.Low;
        entry.Reason = "Custom redirect";
    }

    /// <summary>Back up the current hosts file and replace it with the clean Windows default.</summary>
    public static bool Reset(out string message)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.BackupDir);
            var backup = System.IO.Path.Combine(AppPaths.BackupDir, $"hosts-{DateTime.Now:yyyyMMdd-HHmmss}.bak");
            if (File.Exists(HostsPath)) File.Copy(HostsPath, backup, true);

            const string clean =
                "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n" +
                "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n#\r\n" +
                "# localhost name resolution is handled within DNS itself.\r\n" +
                "#\t127.0.0.1       localhost\r\n#\t::1             localhost\r\n";

            File.SetAttributes(HostsPath, FileAttributes.Normal);
            File.WriteAllText(HostsPath, clean);
            message = "Hosts file reset. Backup saved to " + backup;
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            message = "Administrator rights are needed to reset the hosts file";
            return false;
        }
        catch (Exception ex)
        {
            message = "Could not reset the hosts file: " + ex.Message;
            return false;
        }
    }
}
