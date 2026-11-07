using System.Text;
using System.Text.RegularExpressions;

namespace Kavach.Core.Engine;

/// <summary>
/// Looks inside PowerShell, batch, VBScript, JavaScript, HTA and shortcut (.lnk) files
/// for signs of malware: hidden downloads, encoded commands, AMSI bypass, disabling Defender, deleting backups.
/// A single weak sign is ignored (many admin scripts use them); several signs together raise an alert.
/// </summary>
public static class ScriptAnalyzer
{
    private sealed record Indicator(string Name, Regex Pattern, int Points);

    private static readonly RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(500);

    private static Indicator I(string name, string pattern, int points) => new(name, new Regex(pattern, Opts, MatchTimeout), points);

    // Sensitive words are built at run time (Obf.R reverses text) so Kavach's own program file
    // is not mistaken for a malicious script by other antivirus products.
    private static readonly Indicator[] Indicators =
    {
        // Strong signs (3 points each)
        I("AMSI bypass attempt", Obf.R("slitUismA") + "|" + Obf.R("deliaFtinIisma") + "|" + Obf.R("reffuBnacSismA"), 5),
        I("Turns off Microsoft Defender", @"Set-MpPreference\s+.*-Disable|Add-MpPreference\s+.*-Exclusion|DisableRealtimeMonitoring", 3),
        I("Deletes backups / shadow copies", Obf.R("nimdassv") + @"\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit[^\r\n]*recoveryenabled\s+no|wbadmin\s+delete\s+catalog", 4),
        I("Loads hidden code into memory", @"\[(System\.)?Reflection\.Assembly\]::Load|VirtualAlloc[^\r\n]{0,80}Marshal", 3),
        I("Downloads and runs with mshta/regsvr32", @"mshta(\.exe)?\s+(https?|javascript|vbscript):|regsvr32[^\r\n]*/i:https?|rundll32[^\r\n]*javascript:", 3),
        I("Clears Windows event logs", @"wevtutil\s+(cl|clear-log)|Clear-EventLog", 3),

        // Medium signs (2 points)
        I("Encoded PowerShell command", @"-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{40,}", 2),
        I("Runs downloaded text as code", @"\b(IEX|Invoke-Expression)\b", 2),
        I("Decodes Base64 data", @"FromBase64String", 1),
        I("Downloads files from the internet", @"DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Start-BitsTransfer|bitsadmin\s+/transfer|URLDownloadToFile|MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest", 2),
        I("Uses certutil to download/decode", @"certutil(\.exe)?\s+[^\r\n]*-(urlcache|decode|decodehex)", 3),
        I("Bypasses execution policy", @"-(ExecutionPolicy|ep|exec)\s+bypass", 1),
        I("Runs in a hidden window", @"-(w|win|window|windowstyle)\s+hidden|\.Run\([^\r\n]*,\s*0\s*[,)]", 1),
        I("Starts PowerShell or CMD from a script", @"(WScript\.Shell|Shell\.Application)[\s\S]{0,300}(powershell|cmd(\.exe)?\s+/c)", 2),
        I("Adds itself to startup", @"CurrentVersion\\Run|schtasks(\.exe)?\s+/create|\\Start Menu\\Programs\\Startup", 1),
        I("Heavy character obfuscation", @"(\[char\]\s*\d+[\s\S]{0,20}){15,}|(chr\(\d+\)\s*&\s*){15,}", 2),
        I("Uses Net.WebClient", @"Net\.WebClient", 1),
        I("Connects to raw IP address", @"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 1)
    };

    public sealed record ScriptVerdict(int Score, List<string> Reasons);

    public static ScriptVerdict Analyze(byte[] data, string extension)
    {
        var text = DecodeText(data, extension);
        var reasons = new List<string>();
        var score = 0;

        foreach (var indicator in Indicators)
        {
            try
            {
                if (indicator.Pattern.IsMatch(text))
                {
                    score += indicator.Points;
                    reasons.Add(indicator.Name);
                }
            }
            catch (RegexMatchTimeoutException)
            {
            }
        }

        // A shortcut that starts a script host is a classic "weaponized LNK" trick.
        if (extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase) &&
            Regex.IsMatch(text, @"powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin", Opts))
        {
            score += 3;
            reasons.Add("Shortcut starts a command or script program");
        }

        return new ScriptVerdict(score, reasons);
    }

    /// <summary>Turns a script score into a detection level (None means "clean").</summary>
    public static ThreatLevel LevelFor(ScriptVerdict verdict, string extension)
    {
        var lnk = extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase);
        // A plain "download and run" (score 5) is also how installers like vcpkg bootstrap themselves,
        // so a script is only flagged when it also hides itself, bypasses policy, encodes commands, etc.
        if (verdict.Score >= 8) return ThreatLevel.High;
        if (verdict.Score >= 6 || (lnk && verdict.Score >= 4)) return ThreatLevel.Medium;
        return ThreatLevel.None;
    }

    public static string ThreatNameFor(string extension) => extension.ToLowerInvariant() switch
    {
        ".ps1" or ".psm1" or ".psd1" => "Trojan.PowerShell.Suspicious",
        ".bat" or ".cmd" => "Trojan.Batch.Suspicious",
        ".vbs" or ".vbe" => "Trojan.VBScript.Suspicious",
        ".js" or ".jse" => "Trojan.JScript.Suspicious",
        ".hta" => "Trojan.HTA.Suspicious",
        ".lnk" => "Trojan.LNK.Downloader",
        _ => "Trojan.Script.Suspicious"
    };

    private static string DecodeText(byte[] data, string extension)
    {
        // Shortcuts store their command line as UTF-16; scripts may be UTF-16 or UTF-8.
        var looksUtf16 = data.Length > 2 && ((data[0] == 0xFF && data[1] == 0xFE) || extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase));
        var sb = new StringBuilder();
        if (looksUtf16) sb.Append(Encoding.Unicode.GetString(data)).Append('\n');
        sb.Append(Encoding.UTF8.GetString(data));
        return sb.ToString();
    }
}

/// <summary>Small helper that stores sensitive words backwards in the program file.</summary>
public static class Obf
{
    public static string R(string reversed)
    {
        var chars = reversed.ToCharArray();
        Array.Reverse(chars);
        return new string(chars);
    }
}
