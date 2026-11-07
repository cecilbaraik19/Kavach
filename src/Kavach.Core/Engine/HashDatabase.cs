using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Kavach.Core.Infrastructure;

namespace Kavach.Core.Engine;

/// <summary>Version information saved in Signatures\version.json.</summary>
public sealed class SignatureVersion
{
    public int Version { get; set; } = 1;
    public DateTime Updated { get; set; } = DateTime.Now;
    public string Source { get; set; } = "Bundled";
}

/// <summary>
/// Known-malware SHA-256 hashes.
/// Every .txt / .csv file in the Signatures folder is read. Each line may be:
///   sha256
///   sha256|ThreatName
///   any CSV line containing a 64-character hex hash (for example a MalwareBazaar export)
/// </summary>
public sealed partial class HashDatabase
{
    private Dictionary<string, string> _hashes = new(StringComparer.OrdinalIgnoreCase);

    [GeneratedRegex(@"\b[a-fA-F0-9]{64}\b")]
    private static partial Regex Sha256Regex();

    public int Count => _hashes.Count;
    public SignatureVersion VersionInfo { get; private set; } = new();
    public IReadOnlyList<string> LoadedFiles { get; private set; } = Array.Empty<string>();

    /// <summary>Text used to check if the scan cache is still valid.</summary>
    public string Fingerprint => $"{VersionInfo.Version}:{_hashes.Count}";

    public void Load()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var files = new List<string>();

        if (Directory.Exists(AppPaths.SignaturesDir))
        {
            foreach (var file in Directory.EnumerateFiles(AppPaths.SignaturesDir, "*.*", SearchOption.TopDirectoryOnly))
            {
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".txt" && ext != ".csv") continue;
                if (Path.GetFileName(file).StartsWith("ip_", StringComparison.OrdinalIgnoreCase)) continue;

                files.Add(Path.GetFileName(file));
                var defaultName = Path.GetFileNameWithoutExtension(file).Contains("malwarebazaar", StringComparison.OrdinalIgnoreCase)
                    ? "Malware.MalwareBazaar"
                    : "Malware.KnownHash";

                foreach (var line in ReadLinesShared(file))
                {
                    var (hash, name) = ParseLine(line, defaultName);
                    if (hash != null) map[hash] = name;
                }
            }
        }

        _hashes = map;
        LoadedFiles = files;
        VersionInfo = ReadVersion();
    }

    public bool TryMatch(string sha256, out string threatName)
    {
        if (_hashes.TryGetValue(sha256, out var name))
        {
            threatName = name;
            return true;
        }
        threatName = "";
        return false;
    }

    public static (string? Hash, string Name) ParseLine(string line, string defaultName)
    {
        line = line.Trim();
        if (line.Length == 0 || line.StartsWith('#')) return (null, defaultName);

        // Our own format: hash|Name
        var pipe = line.IndexOf('|');
        if (pipe == 64 && IsHex(line.AsSpan(0, 64)))
        {
            var name = line[(pipe + 1)..].Trim();
            return (line[..64].ToLowerInvariant(), name.Length > 0 ? name : defaultName);
        }

        var match = Sha256Regex().Match(line);
        return match.Success ? (match.Value.ToLowerInvariant(), defaultName) : (null, defaultName);
    }

    /// <summary>All 64-character hashes found in a text (used when importing lists).</summary>
    public static IEnumerable<string> ExtractHashes(string text)
    {
        foreach (Match m in Sha256Regex().Matches(text)) yield return m.Value.ToLowerInvariant();
    }

    public static string ComputeSha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    public static string? ComputeSha256(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    public static SignatureVersion ReadVersion()
    {
        var path = Path.Combine(AppPaths.SignaturesDir, "version.json");
        return JsonStore.Load(path, () => new SignatureVersion());
    }

    public static void BumpVersion(string source)
    {
        var path = Path.Combine(AppPaths.SignaturesDir, "version.json");
        var current = ReadVersion();
        current.Version++;
        current.Updated = DateTime.Now;
        current.Source = source;
        JsonStore.Save(path, current);
    }

    private static bool IsHex(ReadOnlySpan<char> s)
    {
        foreach (var c in s)
        {
            if (!Uri.IsHexDigit(c)) return false;
        }
        return true;
    }

    private static IEnumerable<string> ReadLinesShared(string path)
    {
        List<string> lines = new();
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            string? line;
            while ((line = reader.ReadLine()) != null) lines.Add(line);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch (JsonException) { }
        return lines;
    }
}
