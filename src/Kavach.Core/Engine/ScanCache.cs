using System.Collections.Concurrent;
using Kavach.Core.Infrastructure;

namespace Kavach.Core.Engine;

/// <summary>
/// Remembers files that were clean last time. If a file's size and modified time have not changed,
/// and the signatures are the same version, the file is skipped. This makes repeat scans much faster.
/// </summary>
public sealed class ScanCache
{
    private sealed class CacheFile
    {
        public string Fingerprint { get; set; } = "";
        public Dictionary<string, string> Entries { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private ConcurrentDictionary<string, string> _entries = new(StringComparer.OrdinalIgnoreCase);
    private string _fingerprint = "";
    private int _changes;
    private const int MaxEntries = 400_000;

    public int Count => _entries.Count;

    public void Load(string fingerprint)
    {
        var file = JsonStore.Load(AppPaths.ScanCacheFile, () => new CacheFile());
        _fingerprint = fingerprint;
        _entries = file.Fingerprint == fingerprint
            ? new ConcurrentDictionary<string, string>(file.Entries, StringComparer.OrdinalIgnoreCase)
            : new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Signatures changed: forget everything.</summary>
    public void Reset(string fingerprint)
    {
        _fingerprint = fingerprint;
        _entries.Clear();
        Save();
    }

    private static string Stamp(FileInfo info) => $"{info.Length}:{info.LastWriteTimeUtc.Ticks}";

    public bool IsKnownClean(FileInfo info) =>
        _entries.TryGetValue(info.FullName, out var stamp) && stamp == Stamp(info);

    public void MarkClean(FileInfo info)
    {
        if (_entries.Count >= MaxEntries) return;
        _entries[info.FullName] = Stamp(info);
        Interlocked.Increment(ref _changes);
    }

    public void Forget(string path) => _entries.TryRemove(path, out _);

    public void Save()
    {
        if (Interlocked.Exchange(ref _changes, 0) == 0 && File.Exists(AppPaths.ScanCacheFile)) return;
        var file = new CacheFile
        {
            Fingerprint = _fingerprint,
            Entries = new Dictionary<string, string>(_entries, StringComparer.OrdinalIgnoreCase)
        };
        JsonStore.Save(AppPaths.ScanCacheFile, file);
    }
}
