using System.Text.Json;

namespace Kavach.Core.Infrastructure;

/// <summary>
/// Activity log stored as one JSON object per line (activity.log).
/// Both the app and the service append to it.
/// </summary>
public sealed class ActivityLog
{
    private const long MaxBytes = 5 * 1024 * 1024;
    private static readonly object FileLock = new();

    public event Action<LogEntry>? EntryAdded;

    public void Info(string category, string message) => Write(LogLevel.Info, category, message);
    public void Warning(string category, string message) => Write(LogLevel.Warning, category, message);
    public void Threat(string category, string message) => Write(LogLevel.Threat, category, message);
    public void Error(string category, string message) => Write(LogLevel.Error, category, message);

    public void Write(LogLevel level, string category, string message)
    {
        var entry = new LogEntry { Level = level, Category = category, Message = message, Time = DateTime.Now };
        var line = JsonSerializer.Serialize(entry, JsonStore.Options).Replace("\r", "").Replace("\n", "") + Environment.NewLine;

        lock (FileLock)
        {
            for (var attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    RotateIfTooBig();
                    using var stream = new FileStream(AppPaths.ActivityLogFile, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    using var writer = new StreamWriter(stream);
                    writer.Write(line);
                    break;
                }
                catch (IOException)
                {
                    Thread.Sleep(40);
                }
                catch (UnauthorizedAccessException)
                {
                    break;
                }
            }
        }
        EntryAdded?.Invoke(entry);
    }

    /// <summary>Newest entries first.</summary>
    public List<LogEntry> ReadRecent(int max = 1000)
    {
        var result = new List<LogEntry>();
        try
        {
            if (!File.Exists(AppPaths.ActivityLogFile)) return result;
            using var stream = new FileStream(AppPaths.ActivityLogFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            var lines = new List<string>();
            string? line;
            while ((line = reader.ReadLine()) != null) lines.Add(line);

            for (var i = lines.Count - 1; i >= 0 && result.Count < max; i--)
            {
                try
                {
                    var entry = JsonSerializer.Deserialize<LogEntry>(lines[i], JsonStore.Options);
                    if (entry != null) result.Add(entry);
                }
                catch (JsonException)
                {
                    // skip broken line
                }
            }
        }
        catch
        {
            // ignore read errors
        }
        return result;
    }

    public void Clear()
    {
        lock (FileLock)
        {
            try { File.WriteAllText(AppPaths.ActivityLogFile, ""); } catch { }
        }
    }

    private static void RotateIfTooBig()
    {
        var info = new FileInfo(AppPaths.ActivityLogFile);
        if (info.Exists && info.Length > MaxBytes)
        {
            var old = AppPaths.ActivityLogFile + ".old";
            File.Move(AppPaths.ActivityLogFile, old, true);
        }
    }
}
