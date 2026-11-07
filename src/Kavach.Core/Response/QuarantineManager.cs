using System.Security.Cryptography;
using System.Text;
using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;
using Kavach.Core.Native;

namespace Kavach.Core.Response;

/// <summary>
/// The quarantine vault. A threat is encrypted (AES-256) and moved to C:\ProgramData\Kavach\Quarantine,
/// so it can never run. It can later be restored (false alarm) or deleted for good.
/// </summary>
public sealed class QuarantineManager
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("KAVACHQ1");
    private readonly object _lock = new();
    private readonly ActivityLog _log;
    private readonly SettingsManager _settings;

    public QuarantineManager(ActivityLog log, SettingsManager settings)
    {
        _log = log;
        _settings = settings;
    }

    public event Action? Changed;

    /// <summary>Fixed key derived from the product name; enough to make the file harmless and unreadable.</summary>
    private static byte[] Key => SHA256.HashData(Encoding.UTF8.GetBytes("Kavach quarantine vault • Cecil Baraik"));

    public List<QuarantineItem> List()
    {
        lock (_lock)
        {
            return JsonStore.Load(AppPaths.QuarantineIndexFile, () => new List<QuarantineItem>())
                .OrderByDescending(i => i.QuarantinedAt)
                .ToList();
        }
    }

    public long TotalSize() => List().Sum(i => i.Size);

    public sealed record QuarantineResult(bool Success, string Message, QuarantineItem? Item = null);

    /// <summary>Kill the program if running, encrypt it into the vault and delete the original.</summary>
    public QuarantineResult Quarantine(string path, string threatName, ThreatLevel level)
    {
        if (!File.Exists(path)) return new QuarantineResult(false, "File no longer exists");
        if (AppPaths.IsOwnPath(path)) return new QuarantineResult(false, "Cannot quarantine Kavach's own files");

        byte[] data;
        try
        {
            data = ReadWithRetry(path);
        }
        catch (Exception ex)
        {
            // The file may be locked by the running malware: stop it and try again
            if (ProcessKiller.KillByPath(path) > 0)
            {
                try { data = ReadWithRetry(path); }
                catch (Exception ex2) { return Fail(path, ex2); }
            }
            else
            {
                return Fail(path, ex);
            }
        }

        var item = new QuarantineItem
        {
            OriginalPath = path,
            ThreatName = threatName,
            Level = level,
            Size = data.Length,
            Sha256 = HashDatabase.ComputeSha256(data)
        };
        item.StoredFileName = item.Id + ".cqf";

        try
        {
            Directory.CreateDirectory(AppPaths.QuarantineDir);
            File.WriteAllBytes(Path.Combine(AppPaths.QuarantineDir, item.StoredFileName), Encrypt(data));
        }
        catch (Exception ex)
        {
            return Fail(path, ex);
        }

        // Remove the original
        var deleted = TryDelete(path);
        if (!deleted)
        {
            ProcessKiller.KillByPath(path);
            deleted = TryDelete(path);
        }
        if (!deleted)
        {
            // Still locked: Windows will delete it at the next restart
            NativeMethods.MoveFileEx(path, null, NativeMethods.MOVEFILE_DELAY_UNTIL_REBOOT);
        }

        lock (_lock)
        {
            var list = JsonStore.Load(AppPaths.QuarantineIndexFile, () => new List<QuarantineItem>());

            // The app and the service can catch the same file at the same moment: keep only one copy
            var duplicate = list.FirstOrDefault(i =>
                string.Equals(i.OriginalPath, item.OriginalPath, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(i.Sha256, item.Sha256, StringComparison.OrdinalIgnoreCase) &&
                (item.QuarantinedAt - i.QuarantinedAt).Duration() < TimeSpan.FromMinutes(1));
            if (duplicate != null)
            {
                TryDelete(Path.Combine(AppPaths.QuarantineDir, item.StoredFileName));
                return new QuarantineResult(true, "Moved to quarantine", duplicate);
            }

            list.Add(item);
            JsonStore.Save(AppPaths.QuarantineIndexFile, list);
        }

        _settings.Update(s => s.ThreatsBlockedTotal++);
        _log.Threat("Quarantine", $"Quarantined {threatName}: {path}" + (deleted ? "" : " (original removed at next restart)"));
        Changed?.Invoke();
        return new QuarantineResult(true, deleted ? "Moved to quarantine" : "Quarantined — original will be removed after restart", item);
    }

    /// <summary>Put the file back where it was. Optionally trust it so it is not detected again.</summary>
    public QuarantineResult Restore(string id, bool addToAllowlist)
    {
        var item = Find(id);
        if (item == null) return new QuarantineResult(false, "Item not found");

        try
        {
            var stored = Path.Combine(AppPaths.QuarantineDir, item.StoredFileName);
            var data = Decrypt(File.ReadAllBytes(stored));

            var target = item.OriginalPath;
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            if (File.Exists(target))
            {
                target = Path.Combine(Path.GetDirectoryName(target)!,
                    Path.GetFileNameWithoutExtension(target) + " (restored)" + Path.GetExtension(target));
            }
            File.WriteAllBytes(target, data);

            if (addToAllowlist)
            {
                _settings.Update(s =>
                {
                    if (!s.AllowedHashes.Contains(item.Sha256, StringComparer.OrdinalIgnoreCase)) s.AllowedHashes.Add(item.Sha256);
                });
            }

            RemoveFromIndex(id);
            TryDelete(stored);
            _log.Warning("Quarantine", $"Restored {item.ThreatName} to {target}" + (addToAllowlist ? " and added to allowlist" : ""));
            Changed?.Invoke();
            return new QuarantineResult(true, "Restored to " + target, item);
        }
        catch (Exception ex)
        {
            return new QuarantineResult(false, "Restore failed: " + ex.Message, item);
        }
    }

    public QuarantineResult Delete(string id)
    {
        var item = Find(id);
        if (item == null) return new QuarantineResult(false, "Item not found");
        TryDelete(Path.Combine(AppPaths.QuarantineDir, item.StoredFileName));
        RemoveFromIndex(id);
        _log.Info("Quarantine", $"Permanently deleted {item.ThreatName} ({item.OriginalPath})");
        Changed?.Invoke();
        return new QuarantineResult(true, "Deleted permanently", item);
    }

    public int DeleteAll()
    {
        var count = 0;
        foreach (var item in List())
        {
            if (Delete(item.Id).Success) count++;
        }
        return count;
    }

    private QuarantineItem? Find(string id) => List().FirstOrDefault(i => i.Id == id);

    private void RemoveFromIndex(string id)
    {
        lock (_lock)
        {
            var list = JsonStore.Load(AppPaths.QuarantineIndexFile, () => new List<QuarantineItem>());
            list.RemoveAll(i => i.Id == id);
            JsonStore.Save(AppPaths.QuarantineIndexFile, list);
        }
    }

    private QuarantineResult Fail(string path, Exception ex)
    {
        var message = ex is UnauthorizedAccessException
            ? "Access denied — run Kavach as administrator to quarantine this file"
            : "Could not quarantine: " + ex.Message;
        _log.Error("Quarantine", $"{message} ({path})");
        return new QuarantineResult(false, message);
    }

    private static byte[] ReadWithRetry(string path)
    {
        for (var i = 0; ; i++)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var ms = new MemoryStream();
                stream.CopyTo(ms);
                return ms.ToArray();
            }
            catch (IOException) when (i < 3)
            {
                Thread.Sleep(200);
            }
        }
    }

    private static bool TryDelete(string path)
    {
        try
        {
            if (!File.Exists(path)) return true;
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] Encrypt(byte[] plain)
    {
        using var aes = Aes.Create();
        aes.Key = Key;
        aes.GenerateIV();
        var cipher = aes.EncryptCbc(plain, aes.IV);
        var output = new byte[Magic.Length + aes.IV.Length + cipher.Length];
        Buffer.BlockCopy(Magic, 0, output, 0, Magic.Length);
        Buffer.BlockCopy(aes.IV, 0, output, Magic.Length, aes.IV.Length);
        Buffer.BlockCopy(cipher, 0, output, Magic.Length + aes.IV.Length, cipher.Length);
        return output;
    }

    private static byte[] Decrypt(byte[] stored)
    {
        if (stored.Length < Magic.Length + 16 || !stored.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new InvalidDataException("Not a Kavach quarantine file");
        using var aes = Aes.Create();
        aes.Key = Key;
        var iv = stored.AsSpan(Magic.Length, 16).ToArray();
        var cipher = stored.AsSpan(Magic.Length + 16).ToArray();
        return aes.DecryptCbc(cipher, iv);
    }
}
