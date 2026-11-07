using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace Kavach.Core.Infrastructure;

public sealed record VirusTotalReport(
    bool Found,
    int Malicious,
    int Suspicious,
    int Harmless,
    int Undetected,
    string? Name,
    string? PopularThreat,
    string Link,
    string? Error = null)
{
    public int Total => Malicious + Suspicious + Harmless + Undetected;

    public string Summary =>
        Error != null ? Error :
        !Found ? "Not found on VirusTotal — no one has uploaded this file yet." :
        Malicious > 0 ? $"{Malicious} of {Total} antivirus engines flag this file as malicious" + (PopularThreat != null ? $" ({PopularThreat})" : "") :
        $"Clean: 0 of {Total} engines flag this file";
}

/// <summary>
/// Looks up a file's SHA-256 on VirusTotal (only the hash is sent, never the file).
/// Needs a free API key from virustotal.com (Preferences → Online services).
/// </summary>
public static class VirusTotalClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public static async Task<VirusTotalReport> LookupAsync(string sha256, string? apiKey, CancellationToken token = default)
    {
        var link = $"https://www.virustotal.com/gui/file/{sha256}";
        if (string.IsNullOrWhiteSpace(apiKey))
            return new VirusTotalReport(false, 0, 0, 0, 0, null, null, link, "Add your free VirusTotal API key in Preferences first.");

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
            request.Headers.Add("x-apikey", apiKey.Trim());
            using var response = await Http.SendAsync(request, token);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return new VirusTotalReport(false, 0, 0, 0, 0, null, null, link);
            if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                return new VirusTotalReport(false, 0, 0, 0, 0, null, null, link, "VirusTotal rejected the API key.");
            if ((int)response.StatusCode == 429)
                return new VirusTotalReport(false, 0, 0, 0, 0, null, null, link, "VirusTotal limit reached (4 lookups per minute on free keys). Try again shortly.");
            if (!response.IsSuccessStatusCode)
                return new VirusTotalReport(false, 0, 0, 0, 0, null, null, link, $"VirusTotal error {(int)response.StatusCode}.");

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
            var attributes = doc.RootElement.GetProperty("data").GetProperty("attributes");
            var stats = attributes.GetProperty("last_analysis_stats");

            int Get(string name) => stats.TryGetProperty(name, out var v) && v.TryGetInt32(out var n) ? n : 0;

            string? popular = null;
            if (attributes.TryGetProperty("popular_threat_classification", out var ptc) &&
                ptc.TryGetProperty("suggested_threat_label", out var label))
            {
                popular = label.GetString();
            }

            var name = attributes.TryGetProperty("meaningful_name", out var mn) ? mn.GetString() : null;
            return new VirusTotalReport(true, Get("malicious"), Get("suspicious"), Get("harmless"), Get("undetected"), name, popular, link);
        }
        catch (TaskCanceledException)
        {
            return new VirusTotalReport(false, 0, 0, 0, 0, null, null, link, "VirusTotal did not answer in time.");
        }
        catch (Exception ex)
        {
            return new VirusTotalReport(false, 0, 0, 0, 0, null, null, link, "Lookup failed: " + ex.Message);
        }
    }
}
