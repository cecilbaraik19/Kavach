using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;
using Kavach.Core.Native;

namespace Kavach.Core.SystemChecks;

/// <summary>One open network connection and the program that owns it.</summary>
public sealed class ConnectionInfo
{
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public string State { get; set; } = "";
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ProcessPath { get; set; }
    public ThreatLevel Risk { get; set; }
    public string? Reason { get; set; }

    public string Local => $"{LocalAddress}:{LocalPort}";
    public string Remote => RemotePort == 0 && (RemoteAddress is "0.0.0.0" or "::" or "") ? "—" : $"{RemoteAddress}:{RemotePort}";
    public bool IsFlagged => Risk >= ThreatLevel.Medium;
}

/// <summary>
/// Lists every TCP/UDP connection with the program behind it (like "netstat -ano"),
/// and flags connections to known-bad IP addresses or from unsigned programs in Temp/AppData.
/// </summary>
public static class NetworkMonitor
{
    private static HashSet<string>? _blacklist;
    private static DateTime _blacklistLoaded;

    public static HashSet<string> Blacklist
    {
        get
        {
            if (_blacklist == null || DateTime.Now - _blacklistLoaded > TimeSpan.FromMinutes(5))
            {
                _blacklist = LoadBlacklist();
                _blacklistLoaded = DateTime.Now;
            }
            return _blacklist;
        }
    }

    /// <summary>Reads Signatures\ip_blacklist.txt (one IP per line).</summary>
    public static HashSet<string> LoadBlacklist()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var path = Path.Combine(AppPaths.SignaturesDir, "ip_blacklist.txt");
        try
        {
            if (!File.Exists(path)) return set;
            foreach (var line in File.ReadAllLines(path))
            {
                var t = line.Split('#')[0].Trim();
                if (t.Length > 0 && IPAddress.TryParse(t, out _)) set.Add(t);
            }
        }
        catch
        {
        }
        return set;
    }

    public static List<ConnectionInfo> GetConnections(bool includeUdp = true)
    {
        var processes = new Dictionary<int, string>();
        foreach (var p in Process.GetProcesses())
        {
            try { processes[p.Id] = p.ProcessName; } catch { }
            finally { p.Dispose(); }
        }

        var list = new List<ConnectionInfo>();
        list.AddRange(ReadTcp4());
        list.AddRange(ReadTcp6());
        if (includeUdp) list.AddRange(ReadUdp4());

        var pathCache = new Dictionary<int, string?>();
        var blacklist = Blacklist;

        foreach (var c in list)
        {
            c.ProcessName = c.ProcessId == 0 ? "System Idle" : c.ProcessId == 4 ? "System" :
                processes.TryGetValue(c.ProcessId, out var name) ? name : "(ended)";
            if (!pathCache.TryGetValue(c.ProcessId, out var path))
            {
                path = c.ProcessId > 4 ? NativeMethods.GetProcessImagePath(c.ProcessId) : null;
                pathCache[c.ProcessId] = path;
            }
            c.ProcessPath = path;
            Evaluate(c, blacklist);
        }

        return list.OrderByDescending(c => c.Risk)
                   .ThenBy(c => c.State == "Established" ? 0 : 1)
                   .ThenBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
                   .ToList();
    }

    private static void Evaluate(ConnectionInfo c, HashSet<string> blacklist)
    {
        if (blacklist.Contains(c.RemoteAddress))
        {
            c.Risk = ThreatLevel.Critical;
            c.Reason = "Connected to a known malicious IP address";
            return;
        }

        if (c.State == "Established" && c.ProcessPath != null && IsPublic(c.RemoteAddress) &&
            FileClassifier.IsInUserWritableFolder(c.ProcessPath))
        {
            var sig = SignatureVerifier.Check(c.ProcessPath);
            if (sig.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid)
            {
                c.Risk = ThreatLevel.Medium;
                c.Reason = "Unsigned program from Temp/AppData is talking to the internet";
            }
        }
    }

    private static bool IsPublic(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return false;
        if (IPAddress.IsLoopback(addr) || addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any)) return false;
        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = addr.GetAddressBytes();
            return !(b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254));
        }
        return !addr.IsIPv6LinkLocal && !addr.IsIPv6SiteLocal;
    }

    private static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    private static string StateName(uint state) => state switch
    {
        1 => "Closed",
        2 => "Listening",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => "Unknown"
    };

    private delegate uint TableQuery(IntPtr buffer, ref int size);

    private static List<T> ReadTable<T>(TableQuery query) where T : struct
    {
        const uint ERROR_INSUFFICIENT_BUFFER = 122;
        var result = new List<T>();
        var size = 0;
        query(IntPtr.Zero, ref size); // Windows tells us how big the buffer must be

        for (var attempt = 0; attempt < 5; attempt++)
        {
            size += 4096; // connections can appear between the two calls
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var actual = size;
                var rc = query(buffer, ref actual);
                if (rc == ERROR_INSUFFICIENT_BUFFER)
                {
                    size = actual;
                    continue;
                }
                if (rc != 0) return result;

                var count = Marshal.ReadInt32(buffer);
                var rowSize = Marshal.SizeOf<T>();
                for (var i = 0; i < count; i++)
                {
                    result.Add(Marshal.PtrToStructure<T>(buffer + 4 + i * rowSize));
                }
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return result;
    }

    private static IEnumerable<ConnectionInfo> ReadTcp4()
    {
        var rows = ReadTable<NativeMethods.MIB_TCPROW_OWNER_PID>((IntPtr buf, ref int size) =>
            NativeMethods.GetExtendedTcpTable(buf, ref size, true, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0));
        foreach (var r in rows)
        {
            yield return new ConnectionInfo
            {
                Protocol = "TCP",
                LocalAddress = new IPAddress(r.localAddr).ToString(),
                LocalPort = Port(r.localPort),
                RemoteAddress = new IPAddress(r.remoteAddr).ToString(),
                RemotePort = Port(r.remotePort),
                State = StateName(r.state),
                ProcessId = (int)r.owningPid
            };
        }
    }

    private static IEnumerable<ConnectionInfo> ReadTcp6()
    {
        var rows = ReadTable<NativeMethods.MIB_TCP6ROW_OWNER_PID>((IntPtr buf, ref int size) =>
            NativeMethods.GetExtendedTcpTable(buf, ref size, true, NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0));
        foreach (var r in rows)
        {
            yield return new ConnectionInfo
            {
                Protocol = "TCPv6",
                LocalAddress = new IPAddress(r.localAddr ?? new byte[16]).ToString(),
                LocalPort = Port(r.localPort),
                RemoteAddress = new IPAddress(r.remoteAddr ?? new byte[16]).ToString(),
                RemotePort = Port(r.remotePort),
                State = StateName(r.state),
                ProcessId = (int)r.owningPid
            };
        }
    }

    private static IEnumerable<ConnectionInfo> ReadUdp4()
    {
        var rows = ReadTable<NativeMethods.MIB_UDPROW_OWNER_PID>((IntPtr buf, ref int size) =>
            NativeMethods.GetExtendedUdpTable(buf, ref size, true, NativeMethods.AF_INET, NativeMethods.UDP_TABLE_OWNER_PID, 0));
        foreach (var r in rows)
        {
            yield return new ConnectionInfo
            {
                Protocol = "UDP",
                LocalAddress = new IPAddress(r.localAddr).ToString(),
                LocalPort = Port(r.localPort),
                RemoteAddress = "",
                State = "Listening",
                ProcessId = (int)r.owningPid
            };
        }
    }
}
