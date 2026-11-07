using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;

namespace Kavach.Core.Infrastructure;

/// <summary>
/// Kavach updating itself.
///
/// New versions are published as GitHub Releases (for example tag "v1.2.0") with the
/// KavachSetup-x.y.z.exe installer attached. Kavach asks GitHub for the latest release,
/// compares version numbers, downloads the installer, checks its SHA-256 fingerprint against
/// the one GitHub reports for that file, and then starts it (Windows asks for administrator rights).
/// </summary>
public sealed class AppUpdater
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(10) };
    private readonly KavachContext _ctx;

    public AppUpdater(KavachContext ctx)
    {
        _ctx = ctx;
    }

    public sealed record ReleaseInfo(Version Version, string Tag, string Notes, string AssetName, string DownloadUrl, long Size, string? Sha256);

    public sealed record CheckResult(bool Success, string Message, ReleaseInfo? Update = null);

    public static Version CurrentVersion => Version.TryParse(AppPaths.Version, out var v) ? v : new Version(0, 0);

    /// <summary>Asks GitHub for the newest release. Update is set when it is newer than this copy of Kavach.</summary>
    public async Task<CheckResult> CheckAsync(CancellationToken token = default)
    {
        var repo = (_ctx.Settings.Current.UpdateRepository ?? "").Trim().Trim('/');
        if (repo.Split('/').Length != 2) return new CheckResult(false, "No update source set (Preferences → Updates: owner/repository)");

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{repo}/releases/latest");
            request.Headers.UserAgent.ParseAdd($"Kavach/{AppPaths.Version}");
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var response = await Http.SendAsync(request, token);

            _ctx.Settings.Update(s => s.LastAppUpdateCheck = DateTime.Now);

            if ((int)response.StatusCode == 404)
                return new CheckResult(true, $"You have the latest version (v{AppPaths.Version}). No releases published yet at github.com/{repo}.");
            if (!response.IsSuccessStatusCode)
                return new CheckResult(false, $"Update check failed: {(int)response.StatusCode} {response.ReasonPhrase}");

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
            var root = doc.RootElement;
            var tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
            if (!Version.TryParse(tag.TrimStart('v', 'V'), out var latest))
                return new CheckResult(false, $"The latest release tag \"{tag}\" is not a version number like v1.2.0");

            if (latest <= CurrentVersion)
                return new CheckResult(true, $"You have the latest version (v{AppPaths.Version}).");

            // Find the installer among the release files
            JsonElement? installer = null;
            string? shaFromFile = null;
            if (root.TryGetProperty("assets", out var assets))
            {
                foreach (var a in assets.EnumerateArray())
                {
                    var name = a.GetProperty("name").GetString() ?? "";
                    if (name.StartsWith("KavachSetup", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        installer = a;
                }
                // Optional "KavachSetup-x.y.z.exe.sha256" file next to the installer
                foreach (var a in assets.EnumerateArray())
                {
                    var name = a.GetProperty("name").GetString() ?? "";
                    if (installer != null && name.Equals(installer.Value.GetProperty("name").GetString() + ".sha256", StringComparison.OrdinalIgnoreCase))
                        shaFromFile = await ReadShaFileAsync(a.GetProperty("browser_download_url").GetString()!, token);
                }
            }
            if (installer == null)
                return new CheckResult(false, $"Version {latest} is available, but its release has no KavachSetup .exe attached.");

            var inst = installer.Value;
            // GitHub reports a SHA-256 "digest" for every uploaded file
            string? sha = shaFromFile;
            if (sha == null && inst.TryGetProperty("digest", out var d) && d.ValueKind == JsonValueKind.String)
            {
                var digest = d.GetString() ?? "";
                if (digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)) sha = digest[7..];
            }

            var info = new ReleaseInfo(
                latest,
                tag,
                root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "",
                inst.GetProperty("name").GetString() ?? "KavachSetup.exe",
                inst.GetProperty("browser_download_url").GetString() ?? "",
                inst.TryGetProperty("size", out var sz) ? sz.GetInt64() : 0,
                sha?.ToLowerInvariant());

            return new CheckResult(true, $"Kavach v{latest} is available (you have v{AppPaths.Version}).", info);
        }
        catch (TaskCanceledException)
        {
            return new CheckResult(false, "Update check timed out. Check your internet connection.");
        }
        catch (Exception ex)
        {
            return new CheckResult(false, "Update check failed: " + ex.Message);
        }
    }

    /// <summary>Downloads the installer and checks its fingerprint. Returns the local file path.</summary>
    public async Task<(bool Success, string Message, string? Path)> DownloadAsync(ReleaseInfo release, IProgress<double>? progress = null,
        CancellationToken token = default)
    {
        if (string.IsNullOrEmpty(release.Sha256))
            return (false, "This release has no SHA-256 fingerprint, so Kavach cannot check the download is genuine. Download it from GitHub yourself.", null);
        if (!release.DownloadUrl.StartsWith("https://github.com/", StringComparison.OrdinalIgnoreCase))
            return (false, "Unexpected download address — update cancelled.", null);

        try
        {
            var folder = Path.Combine(AppPaths.DataDir, "Updates");
            Directory.CreateDirectory(folder);
            var safeName = string.Concat(release.AssetName.Where(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_'));
            var target = Path.Combine(folder, safeName);

            using var request = new HttpRequestMessage(HttpMethod.Get, release.DownloadUrl);
            request.Headers.UserAgent.ParseAdd($"Kavach/{AppPaths.Version}");
            using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
            if (!response.IsSuccessStatusCode) return (false, $"Download failed: {(int)response.StatusCode} {response.ReasonPhrase}", null);

            var total = response.Content.Headers.ContentLength ?? release.Size;
            using (var input = await response.Content.ReadAsStreamAsync(token))
            using (var output = File.Create(target))
            {
                var buffer = new byte[81920];
                long done = 0;
                int read;
                while ((read = await input.ReadAsync(buffer, token)) > 0)
                {
                    await output.WriteAsync(buffer.AsMemory(0, read), token);
                    done += read;
                    if (total > 0) progress?.Report((double)done / total);
                }
            }

            // Check the fingerprint: a changed or damaged file is deleted, never run
            string actual;
            using (var stream = File.OpenRead(target)) actual = Convert.ToHexString(await SHA256.HashDataAsync(stream, token)).ToLowerInvariant();
            if (!actual.Equals(release.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(target);
                _ctx.Log.Warning("Updates", $"Downloaded installer fingerprint did not match ({actual} ≠ {release.Sha256}) — deleted");
                return (false, "The downloaded file's fingerprint does not match — it was deleted and not run.", null);
            }

            _ctx.Log.Info("Updates", $"Downloaded Kavach v{release.Version} installer, SHA-256 verified");
            return (true, "Download complete and verified", target);
        }
        catch (Exception ex)
        {
            return (false, "Download failed: " + ex.Message, null);
        }
    }

    /// <summary>Starts the verified installer. Windows shows the administrator prompt; the installer closes Kavach and restarts it.</summary>
    public bool StartInstaller(string path, out string message)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                Arguments = "/SILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS",
                UseShellExecute = true,
                Verb = "runas"
            });
            _ctx.Log.Info("Updates", "Started the Kavach update installer");
            message = "Installing the update — Kavach will restart by itself.";
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            message = "Update cancelled (administrator permission was not given).";
            return false;
        }
        catch (Exception ex)
        {
            message = "Could not start the installer: " + ex.Message;
            return false;
        }
    }

    private static async Task<string?> ReadShaFileAsync(string url, CancellationToken token)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.ParseAdd($"Kavach/{AppPaths.Version}");
            using var response = await Http.SendAsync(request, token);
            if (!response.IsSuccessStatusCode) return null;
            var text = await response.Content.ReadAsStringAsync(token);
            var hash = text.Split(new[] { ' ', '\t', '\r', '\n', '*' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            return hash is { Length: 64 } && hash.All(Uri.IsHexDigit) ? hash : null;
        }
        catch
        {
            return null;
        }
    }
}
