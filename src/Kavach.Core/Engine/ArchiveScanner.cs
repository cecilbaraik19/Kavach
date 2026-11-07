using SharpCompress.Archives;

namespace Kavach.Core.Engine;

/// <summary>
/// Opens ZIP, RAR, 7z, TAR and GZ archives and scans each file inside.
/// Limits protect against "zip bombs" (tiny archives that unpack to gigabytes).
/// </summary>
public static class ArchiveScanner
{
    private const int MaxEntries = 500;
    private const long MaxEntrySize = 50L * 1024 * 1024;
    private const long MaxTotalSize = 200L * 1024 * 1024;

    public delegate void EntryHandler(string innerPath, byte[] content);

    /// <summary>Calls <paramref name="onEntry"/> for every file inside. Returns extra detections (encrypted executables, bombs).</summary>
    public static List<Detection> Explore(byte[] archiveData, string archivePath, string innerPrefix, EntryHandler onEntry, CancellationToken token)
    {
        var detections = new List<Detection>();
        try
        {
            using var stream = new MemoryStream(archiveData, writable: false);
            using var archive = ArchiveFactory.Open(stream);

            var count = 0;
            long total = 0;
            foreach (var entry in archive.Entries)
            {
                token.ThrowIfCancellationRequested();
                if (entry.IsDirectory) continue;
                if (++count > MaxEntries) break;

                var name = entry.Key ?? "(unnamed)";
                var inner = innerPrefix.Length == 0 ? name : innerPrefix + " › " + name;
                var ext = Path.GetExtension(name);

                if (entry.IsEncrypted)
                {
                    if (FileClassifier.ExecutableExtensions.Contains(ext) || FileClassifier.ScriptExtensions.Contains(ext))
                    {
                        detections.Add(new Detection
                        {
                            FilePath = archivePath,
                            InnerPath = inner,
                            ThreatName = "Suspicious.EncryptedArchive.Executable",
                            Level = ThreatLevel.Medium,
                            Source = DetectionSource.Archive,
                            Details = "Password-protected archive containing a program — a common way to sneak malware past antivirus"
                        });
                    }
                    continue;
                }

                if (entry.Size > MaxEntrySize) continue;
                total += entry.Size;
                if (total > MaxTotalSize)
                {
                    if (archiveData.Length < 1024 * 1024)
                    {
                        detections.Add(new Detection
                        {
                            FilePath = archivePath,
                            ThreatName = "Suspicious.ArchiveBomb",
                            Level = ThreatLevel.Medium,
                            Source = DetectionSource.Archive,
                            Details = "Very small archive that unpacks to a huge size (zip bomb)"
                        });
                    }
                    break;
                }

                byte[] content;
                using (var entryStream = entry.OpenEntryStream())
                using (var buffer = new MemoryStream())
                {
                    CopyLimited(entryStream, buffer, MaxEntrySize);
                    content = buffer.ToArray();
                }
                onEntry(inner, content);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Not an archive, damaged, or an unsupported format: nothing more to scan.
        }
        return detections;
    }

    private static void CopyLimited(Stream source, Stream target, long max)
    {
        var buffer = new byte[81920];
        long copied = 0;
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            copied += read;
            if (copied > max) break;
            target.Write(buffer, 0, read);
        }
    }
}
