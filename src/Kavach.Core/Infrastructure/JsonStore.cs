using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kavach.Core.Infrastructure;

/// <summary>
/// Saves and loads objects as JSON files.
/// Writes go to a temporary file first, then replace the real file, so a crash never leaves a half-written file.
/// </summary>
public static class JsonStore
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static T Load<T>(string path, Func<T> createDefault)
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                if (!File.Exists(path)) return createDefault();
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var value = JsonSerializer.Deserialize<T>(stream, Options);
                return value ?? createDefault();
            }
            catch (IOException)
            {
                Thread.Sleep(60); // another process (app or service) is writing; try again
            }
            catch (JsonException)
            {
                return createDefault(); // damaged file: start fresh
            }
            catch (UnauthorizedAccessException)
            {
                return createDefault();
            }
        }
        return createDefault();
    }

    public static bool Save<T>(string path, T value)
    {
        var temp = path + "." + Environment.ProcessId + ".tmp";
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(temp, JsonSerializer.Serialize(value, Options));
                File.Move(temp, path, true);
                return true;
            }
            catch (IOException)
            {
                Thread.Sleep(60);
            }
            catch (UnauthorizedAccessException)
            {
                break;
            }
        }
        try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        return false;
    }
}
