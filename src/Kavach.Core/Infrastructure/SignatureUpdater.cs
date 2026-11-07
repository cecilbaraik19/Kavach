using System.IO.Compression;
using System.Net.Http;
using System.Text;
using Kavach.Core.Engine;

namespace Kavach.Core.Infrastructure;

/// <summary>Downloads and imports new signatures (hash lists and rules).</summary>
public sealed class SignatureUpdater
{
    private readonly KavachContext _ctx;
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(120) };

    public SignatureUpdater(KavachContext ctx)
    {
        _ctx = ctx;
    }

    public sealed record UpdateResult(bool Success, string Message, int Added = 0);

    // Free, public YARA rules from ReversingLabs (MIT licence) — no account or key needed
    private const string RulesZipUrl = "https://codeload.github.com/reversinglabs/reversinglabs-yara-rules/zip/refs/heads/develop";
    private const string OnlineRulesFile = "online_reversinglabs.yar";

    /// <summary>
    /// "Download latest": always fetches the free online rules; also fetches MalwareBazaar hashes
    /// when the user has added an abuse.ch Auth-Key (optional).
    /// </summary>
    public async Task<UpdateResult> DownloadAllAsync(CancellationToken token = default)
    {
        var rules = await DownloadOnlineRulesAsync(token);
        if (string.IsNullOrWhiteSpace(_ctx.Settings.Current.AbuseChAuthKey)) return rules;

        var hashes = await DownloadMalwareBazaarAsync(token);
        return new UpdateResult(rules.Success || hashes.Success, rules.Message + " • " + hashes.Message, rules.Added + hashes.Added);
    }

    /// <summary>
    /// Downloads the ReversingLabs YARA rule collection from GitHub (one ZIP file), keeps every
    /// Windows rule that Kavach's rule engine fully understands, and saves them as one rule file.
    /// </summary>
    public async Task<UpdateResult> DownloadOnlineRulesAsync(CancellationToken token = default)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, RulesZipUrl);
            request.Headers.UserAgent.ParseAdd($"Kavach/{AppPaths.Version}");
            using var response = await Http.SendAsync(request, token);
            if (!response.IsSuccessStatusCode)
                return new UpdateResult(false, $"Rule download failed: {(int)response.StatusCode} {response.ReasonPhrase}");

            var zipBytes = await response.Content.ReadAsByteArrayAsync(token);
            var output = new StringBuilder();
            output.AppendLine("// Kavach online rules — downloaded " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
            output.AppendLine("// Source: https://github.com/reversinglabs/reversinglabs-yara-rules");
            output.AppendLine("// Copyright (c) ReversingLabs — MIT License. Only rules Kavach's engine fully supports are kept.");
            output.AppendLine();

            int files = 0, kept = 0, skipped = 0;
            using (var zip = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read))
            {
                foreach (var entry in zip.Entries)
                {
                    var path = entry.FullName.Replace('\\', '/');
                    if (!path.Contains("/yara/") || !path.EndsWith(".yara", StringComparison.OrdinalIgnoreCase)) continue;
                    if (entry.Length > 2 * 1024 * 1024) continue;

                    // Kavach protects Windows: skip Linux/macOS rules, adware (PUA) and certificate rules
                    var name = Path.GetFileName(path);
                    if (path.Contains("/pua/") || path.Contains("/certificate/")) continue;
                    if (name.StartsWith("Linux", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("MacOS", StringComparison.OrdinalIgnoreCase)) continue;

                    files++;
                    string text;
                    using (var reader = new StreamReader(entry.Open())) text = await reader.ReadToEndAsync(token);

                    // Files that need YARA modules (pe, math …) or unsupported syntax are left out completely
                    var errors = new List<string>();
                    var count = text.Contains("import \"") ? 0 : RuleSet.Validate(text, name, errors);
                    if (count == 0 || errors.Count > 0)
                    {
                        skipped++;
                        continue;
                    }

                    output.AppendLine("// ---- " + path[(path.IndexOf("/yara/", StringComparison.Ordinal) + 1)..]);
                    output.AppendLine(text);
                    kept += count;
                }
            }

            if (kept == 0) return new UpdateResult(false, "The download did not contain any usable rules");

            var target = Path.Combine(AppPaths.RulesDir, OnlineRulesFile);
            var previous = File.Exists(target) ? RuleSet.Validate(await File.ReadAllTextAsync(target, token), OnlineRulesFile, new List<string>()) : 0;
            await File.WriteAllTextAsync(target, output.ToString(), token);

            HashDatabase.BumpVersion("ReversingLabs rules");
            _ctx.ReloadSignatures();
            _ctx.Settings.Update(s => s.LastOnlineRulesUpdate = DateTime.Now);
            _ctx.Log.Info("Updates", $"Downloaded online rules: {kept} rules from {files - skipped} files ({skipped} files skipped — unsupported features)");
            var added = Math.Max(0, kept - previous);
            return new UpdateResult(true, $"Rules updated: {kept} online detection rules ({added} new)", added);
        }
        catch (TaskCanceledException)
        {
            return new UpdateResult(false, "Download timed out. Check your internet connection.");
        }
        catch (Exception ex)
        {
            return new UpdateResult(false, "Rule update failed: " + ex.Message);
        }
    }

    /// <summary>
    /// Downloads the latest malware hashes shared by abuse.ch MalwareBazaar (last 48 hours of new samples).
    /// abuse.ch may require a free Auth-Key — add it in Preferences → Online services.
    /// </summary>
    public async Task<UpdateResult> DownloadMalwareBazaarAsync(CancellationToken token = default)
    {
        var key = _ctx.Settings.Current.AbuseChAuthKey?.Trim();
        if (string.IsNullOrEmpty(key))
        {
            return new UpdateResult(false,
                "MalwareBazaar now needs a free Auth-Key. Get one at auth.abuse.ch, paste it in Preferences → Online services, then try again.");
        }

        try
        {
            // Recent additions (last 48 hours, refreshed every 5 minutes). Please do not download more often than that.
            var url = $"https://mb-api.abuse.ch/v2/files/exports/{Uri.EscapeDataString(key)}/recent.csv";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.ParseAdd($"Kavach/{AppPaths.Version}");
            request.Headers.Add("Auth-Key", key);

            using var response = await Http.SendAsync(request, token);
            if (!response.IsSuccessStatusCode)
            {
                var hint = (int)response.StatusCode is 401 or 403
                    ? " — check your abuse.ch Auth-Key in Preferences"
                    : "";
                return new UpdateResult(false, $"Download failed: {(int)response.StatusCode} {response.ReasonPhrase}{hint}");
            }

            var text = await response.Content.ReadAsStringAsync(token);
            var hashes = HashDatabase.ExtractHashes(text).ToList();
            if (hashes.Count == 0) return new UpdateResult(false, "The download did not contain any hashes");

            var target = Path.Combine(AppPaths.SignaturesDir, "malwarebazaar_recent.txt");
            var existing = File.Exists(target)
                ? HashDatabase.ExtractHashes(await File.ReadAllTextAsync(target, token)).ToHashSet()
                : new HashSet<string>();
            var added = hashes.Count(h => existing.Add(h));

            // Keep the newest 500,000 hashes so the file does not grow forever
            var lines = new List<string>
            {
                $"# MalwareBazaar recent SHA-256 hashes — updated {DateTime.Now:yyyy-MM-dd HH:mm}",
                "# Source: https://bazaar.abuse.ch (CC0)"
            };
            lines.AddRange(existing.Take(500_000).Select(h => h + "|Malware.MalwareBazaar"));
            await File.WriteAllLinesAsync(target, lines, token);

            HashDatabase.BumpVersion("MalwareBazaar");
            _ctx.ReloadSignatures();
            _ctx.Log.Info("Updates", $"Downloaded MalwareBazaar hashes: {added:N0} new, {existing.Count:N0} in list");
            return new UpdateResult(true, $"Updated: {added:N0} new malware hashes added", added);
        }
        catch (TaskCanceledException)
        {
            return new UpdateResult(false, "Download timed out. Check your internet connection.");
        }
        catch (Exception ex)
        {
            return new UpdateResult(false, "Update failed: " + ex.Message);
        }
    }

    /// <summary>Imports any text/CSV file containing SHA-256 hashes (e.g. a MalwareBazaar CSV export).</summary>
    public UpdateResult ImportHashFile(string path)
    {
        try
        {
            var hashes = HashDatabase.ExtractHashes(File.ReadAllText(path)).Distinct().ToList();
            if (hashes.Count == 0) return new UpdateResult(false, "No SHA-256 hashes found in that file");

            var target = Path.Combine(AppPaths.SignaturesDir, "custom_hashes.txt");
            var existing = File.Exists(target)
                ? HashDatabase.ExtractHashes(File.ReadAllText(target)).ToHashSet()
                : new HashSet<string>();
            var name = "Malware." + MakeSafeName(Path.GetFileNameWithoutExtension(path));
            var newOnes = hashes.Where(h => existing.Add(h)).ToList();
            File.AppendAllLines(target, newOnes.Select(h => $"{h}|{name}"));

            HashDatabase.BumpVersion("Import");
            _ctx.ReloadSignatures();
            _ctx.Log.Info("Updates", $"Imported {newOnes.Count:N0} hashes from {Path.GetFileName(path)}");
            return new UpdateResult(true, $"Imported {newOnes.Count:N0} new hashes", newOnes.Count);
        }
        catch (Exception ex)
        {
            return new UpdateResult(false, "Import failed: " + ex.Message);
        }
    }

    /// <summary>Adds a single hash (for example from a news report) to the custom list.</summary>
    public UpdateResult AddHash(string sha256, string threatName)
    {
        var hash = HashDatabase.ExtractHashes(sha256).FirstOrDefault();
        if (hash == null) return new UpdateResult(false, "That is not a valid SHA-256 hash (64 hex characters)");
        var target = Path.Combine(AppPaths.SignaturesDir, "custom_hashes.txt");
        File.AppendAllLines(target, new[] { $"{hash}|{(string.IsNullOrWhiteSpace(threatName) ? "Malware.Custom" : threatName.Trim())}" });
        HashDatabase.BumpVersion("Manual");
        _ctx.ReloadSignatures();
        return new UpdateResult(true, "Hash added", 1);
    }

    /// <summary>Validates and copies a .yar/.yara rule file into the rules folder.</summary>
    public UpdateResult ImportRuleFile(string path)
    {
        try
        {
            var text = File.ReadAllText(path);
            var errors = new List<string>();
            var count = RuleSet.Validate(text, Path.GetFileName(path), errors);
            if (count == 0)
            {
                return new UpdateResult(false, errors.Count > 0
                    ? "No usable rules. " + errors[0]
                    : "No rules found in that file");
            }

            var target = Path.Combine(AppPaths.RulesDir, "imported_" + Path.GetFileName(path));
            if (!target.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) && !target.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
                target += ".yar";
            File.Copy(path, target, true);

            HashDatabase.BumpVersion("Rules import");
            _ctx.ReloadSignatures();
            var message = $"Imported {count} rule(s)" + (errors.Count > 0 ? $" — {errors.Count} skipped (unsupported features)" : "");
            _ctx.Log.Info("Updates", message + $" from {Path.GetFileName(path)}");
            return new UpdateResult(true, message, count);
        }
        catch (Exception ex)
        {
            return new UpdateResult(false, "Import failed: " + ex.Message);
        }
    }

    private static string MakeSafeName(string s)
    {
        var chars = s.Where(c => char.IsLetterOrDigit(c) || c == '_' || c == '-').ToArray();
        var name = new string(chars);
        return name.Length == 0 ? "Imported" : name;
    }
}
