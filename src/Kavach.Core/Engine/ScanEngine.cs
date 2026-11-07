using Kavach.Core.Infrastructure;

namespace Kavach.Core.Engine;

public sealed class ScanFileOptions
{
    /// <summary>Quick/Full scans only open file types that can carry malware.</summary>
    public bool OnlyInteresting { get; init; }
    public bool UseCache { get; init; } = true;

    public static readonly ScanFileOptions Default = new();
    public static readonly ScanFileOptions Interesting = new() { OnlyInteresting = true };
    public static readonly ScanFileOptions NoCache = new() { UseCache = false };
    /// <summary>Real-time protection: only file types that can run code, always fresh.</summary>
    public static readonly ScanFileOptions RealTime = new() { OnlyInteresting = true, UseCache = false };
}

/// <summary>
/// The heart of the antivirus. Decides whether one file is malicious by running every detection method:
///   1. File name checks (double extension, fake system file, look-alike name)
///   2. SHA-256 hash against the known-malware list
///   3. YARA-style rules
///   4. PE heuristics for programs (.exe / .dll)
///   5. Script analysis (PowerShell, VBScript, batch, shortcuts …)
///   6. Archive scanning (files inside ZIP / RAR / 7z)
/// </summary>
public sealed class ScanEngine
{
    private const int MaxRuleBytes = 32 * 1024 * 1024;
    private readonly SettingsManager _settings;

    public ScanEngine(SettingsManager settings, HashDatabase hashes, RuleSet rules, ScanCache cache)
    {
        _settings = settings;
        Hashes = hashes;
        Rules = rules;
        Cache = cache;
    }

    public HashDatabase Hashes { get; }
    public RuleSet Rules { get; }
    public ScanCache Cache { get; }

    public FileVerdict ScanFile(string path, ScanFileOptions options, CancellationToken token = default)
    {
        var verdict = new FileVerdict(path);
        var settings = _settings.Current;

        try
        {
            if (AppPaths.IsOwnPath(path)) return Skip(verdict, "Kavach file");
            if (_settings.IsExcluded(path)) return Skip(verdict, "Excluded by you");

            var info = new FileInfo(path);
            if (!info.Exists) return Skip(verdict, "File no longer exists");
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 && info.Length == 0) return Skip(verdict, "Link / cloud placeholder");
            // Cloud files that are not downloaded (OneDrive "online-only") would be downloaded by reading them
            if ((info.Attributes & (FileAttributes)0x00400000) != 0) return Skip(verdict, "Online-only cloud file");

            if (options.OnlyInteresting && !FileClassifier.IsInteresting(path) && !StartsWithMz(path))
                return Skip(verdict, "File type cannot run code");

            if (settings.SkipMediaFiles && FileClassifier.IsMedia(path) && info.Length > 2 * 1024 * 1024)
                return Skip(verdict, "Media file");

            // 1. Name checks (cheap, no reading needed)
            verdict.Detections.AddRange(FileClassifier.CheckName(path));

            var maxBytes = Math.Max(1, settings.MaxFileSizeMb) * 1024L * 1024L;
            if (info.Length > maxBytes)
            {
                if (verdict.IsThreat) return verdict;
                return Skip(verdict, $"Larger than {settings.MaxFileSizeMb} MB");
            }

            if (options.UseCache && settings.UseScanCache && !verdict.IsThreat && Cache.IsKnownClean(info))
            {
                verdict.FromCache = true;
                return verdict;
            }

            byte[] data;
            try
            {
                data = ReadShared(path);
            }
            catch (IOException)
            {
                if (verdict.IsThreat) return verdict;
                return Skip(verdict, "File is in use");
            }
            catch (UnauthorizedAccessException)
            {
                if (verdict.IsThreat) return verdict;
                return Skip(verdict, "Access denied (run as administrator)");
            }

            verdict.Sha256 = HashDatabase.ComputeSha256(data);

            // Allowlisted by the user ("not a virus")
            if (_settings.IsHashAllowed(verdict.Sha256))
            {
                verdict.Detections.Clear();
                return verdict;
            }

            ScanContent(path, null, Path.GetFileName(path), data, info.Length, depth: 0, verdict.Detections, onDisk: true, token, verdict.Sha256);

            foreach (var d in verdict.Detections)
            {
                d.FilePath = path;
                d.Sha256 ??= verdict.Sha256;
            }

            if (!verdict.IsThreat && settings.UseScanCache) Cache.MarkClean(info);
            if (verdict.IsThreat) Cache.Forget(path);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            verdict.Skipped = true;
            verdict.SkipReason = "Error: " + ex.Message;
        }
        return verdict;
    }

    /// <summary>Scans bytes that are already in memory (used for archives and downloads).</summary>
    public void ScanContent(string diskPath, string? innerPath, string fileName, byte[] data, long size, int depth,
        List<Detection> results, bool onDisk, CancellationToken token, string? knownSha256 = null)
    {
        token.ThrowIfCancellationRequested();
        var settings = _settings.Current;
        var ext = Path.GetExtension(fileName);
        var hashToCheck = knownSha256 ?? HashDatabase.ComputeSha256(data);

        // Files inside archives also get name checks
        if (innerPath != null)
        {
            foreach (var d in FileClassifier.CheckName(fileName))
            {
                d.InnerPath = innerPath;
                d.FilePath = diskPath;
                results.Add(d);
            }
        }

        // 2. Known malware hash
        if (Hashes.TryMatch(hashToCheck, out var knownName))
        {
            results.Add(new Detection
            {
                FilePath = diskPath,
                InnerPath = innerPath,
                ThreatName = knownName,
                Level = ThreatLevel.Critical,
                Source = DetectionSource.Hash,
                Sha256 = hashToCheck,
                Details = "Exact match with a known malware file"
            });
            return; // no need for more checks
        }

        var isPe = PeAnalyzer.LooksLikePe(data);
        var isScript = FileClassifier.ScriptExtensions.Contains(ext);
        var trusted = new Lazy<bool>(() => onDisk && innerPath == null && IsTrustedSigned(diskPath));

        // 3. YARA-style rules
        var ruleData = data.Length > MaxRuleBytes ? data.AsSpan(0, MaxRuleBytes).ToArray() : data;
        foreach (var match in Rules.Match(ruleData, size))
        {
            if (trusted.Value) continue; // signed by a real publisher or part of Windows
            results.Add(new Detection
            {
                FilePath = diskPath,
                InnerPath = innerPath,
                ThreatName = match.Rule.ThreatName,
                Level = match.Rule.Level,
                Source = DetectionSource.Rule,
                Sha256 = hashToCheck,
                Details = (match.Rule.Description.Length > 0 ? match.Rule.Description + " — " : "") +
                          $"rule {match.Rule.Name}" +
                          (match.MatchedStrings.Count > 0 ? $" ({string.Join(", ", match.MatchedStrings.Take(4))})" : "")
            });
        }

        // 4. PE heuristics
        if (isPe)
        {
            var pe = PeAnalyzer.Parse(data);
            var score = PeAnalyzer.Score(pe);
            if (score.Score >= 45 && !trusted.Value)
            {
                // Unsigned programs in Temp/AppData are more suspicious
                if (onDisk && innerPath == null && FileClassifier.IsInUserWritableFolder(diskPath))
                {
                    var sig = SignatureVerifier.Check(diskPath);
                    if (sig.Status is SignatureStatus.Unsigned or SignatureStatus.Invalid)
                        score.Add(10, "Unsigned program in a user-writable folder");
                }

                results.Add(new Detection
                {
                    FilePath = diskPath,
                    InnerPath = innerPath,
                    ThreatName = score.Score >= 70 ? "Heuristic.Suspicious.PE" : "Heuristic.Suspicious.PE.Low",
                    Level = score.Score >= 70 ? ThreatLevel.High : ThreatLevel.Medium,
                    Source = DetectionSource.Heuristic,
                    Sha256 = hashToCheck,
                    Details = $"Score {score.Score}: " + string.Join("; ", score.Reasons)
                });
            }
        }

        // 5. Scripts and shortcuts
        if (isScript && data.Length <= 5 * 1024 * 1024 && !trusted.Value)
        {
            var script = ScriptAnalyzer.Analyze(data, ext);
            var level = ScriptAnalyzer.LevelFor(script, ext);
            if (level != ThreatLevel.None)
            {
                results.Add(new Detection
                {
                    FilePath = diskPath,
                    InnerPath = innerPath,
                    ThreatName = ScriptAnalyzer.ThreatNameFor(ext),
                    Level = level,
                    Source = DetectionSource.Script,
                    Sha256 = hashToCheck,
                    Details = string.Join("; ", script.Reasons)
                });
            }
        }

        // 6. Archives (recursive, limited depth)
        if (settings.ScanArchives && depth < Math.Max(1, settings.MaxArchiveDepth) && LooksLikeArchive(data, ext))
        {
            var prefix = innerPath ?? "";
            var extra = ArchiveScanner.Explore(data, diskPath, prefix, (inner, content) =>
            {
                ScanContent(diskPath, inner, Path.GetFileName(inner), content, content.Length, depth + 1, results, onDisk: false, token);
            }, token);
            results.AddRange(extra);
        }
    }

    private static bool LooksLikeArchive(byte[] data, string ext)
    {
        if (FileClassifier.ArchiveExtensions.Contains(ext)) return true;
        if (data.Length < 4) return false;
        // ZIP "PK\3\4", RAR "Rar!", 7z "7z\xBC\xAF", GZip 1F 8B
        return (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 && !ext.StartsWith(".doc", StringComparison.OrdinalIgnoreCase)
                                                                                     && !ext.StartsWith(".xls", StringComparison.OrdinalIgnoreCase)
                                                                                     && !ext.StartsWith(".ppt", StringComparison.OrdinalIgnoreCase))
               || (data[0] == 0x52 && data[1] == 0x61 && data[2] == 0x72 && data[3] == 0x21)
               || (data[0] == 0x37 && data[1] == 0x7A && data[2] == 0xBC && data[3] == 0xAF)
               || (data[0] == 0x1F && data[1] == 0x8B);
    }

    /// <summary>
    /// A file with a valid digital signature (for example Firefox or Rufus downloads) or a file that is part of
    /// Windows is trusted, so heuristics and rules do not raise false alarms on it. Known-malware hashes still apply.
    /// </summary>
    private static bool IsTrustedSigned(string path)
    {
        if (IsWindowsCatalogFile(path)) return true;
        return SignatureVerifier.Check(path).IsTrusted;
    }

    /// <summary>Most Windows system files are signed through catalogs, not inside the file.</summary>
    private static bool IsWindowsCatalogFile(string path)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return windows.Length > 0
               && path.StartsWith(windows + "\\", StringComparison.OrdinalIgnoreCase)
               && !path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase);
    }

    private static FileVerdict Skip(FileVerdict verdict, string reason)
    {
        verdict.Skipped = true;
        verdict.SkipReason = reason;
        return verdict;
    }

    private static byte[] ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
        var length = (int)Math.Min(stream.Length, int.MaxValue - 64);
        var buffer = new byte[length];
        var read = 0;
        while (read < length)
        {
            var n = stream.Read(buffer, read, length - read);
            if (n == 0) break;
            read += n;
        }
        if (read < length) Array.Resize(ref buffer, read);
        return buffer;
    }

    private static bool StartsWithMz(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return stream.ReadByte() == 'M' && stream.ReadByte() == 'Z';
        }
        catch
        {
            return false;
        }
    }
}
