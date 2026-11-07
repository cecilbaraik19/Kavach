using System.Globalization;
using System.Text;

namespace Kavach.Core.Infrastructure;

public enum ReportFormat
{
    Text,
    Csv,
    Pdf
}

/// <summary>Saves a scan report as a text, CSV or PDF file.</summary>
public static class ReportExporter
{
    public static void Export(ScanSummary scan, string path, ReportFormat format)
    {
        switch (format)
        {
            case ReportFormat.Csv:
                File.WriteAllText(path, BuildCsv(scan), new UTF8Encoding(true));
                break;
            case ReportFormat.Pdf:
                File.WriteAllBytes(path, SimplePdf.Create("Kavach Antivirus — Scan Report", BuildLines(scan)));
                break;
            default:
                File.WriteAllText(path, string.Join(Environment.NewLine, BuildLines(scan)), Encoding.UTF8);
                break;
        }
    }

    public static ReportFormat FormatFromExtension(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".csv" => ReportFormat.Csv,
        ".pdf" => ReportFormat.Pdf,
        _ => ReportFormat.Text
    };

    public static List<string> BuildLines(ScanSummary scan)
    {
        var lines = new List<string>
        {
            "KAVACH ANTIVIRUS — SCAN REPORT",
            $"Developed by {AppPaths.Publisher}  •  Version {AppPaths.Version}",
            new string('=', 70),
            $"Computer:        {Environment.MachineName}",
            $"Scan type:       {scan.Type}",
            $"Status:          {scan.Status}",
            $"Started:         {scan.Started:dd MMM yyyy, hh:mm:ss tt}",
            $"Finished:        {(scan.Finished.HasValue ? scan.Finished.Value.ToString("dd MMM yyyy, hh:mm:ss tt", CultureInfo.InvariantCulture) : "-")}",
            $"Duration:        {scan.Duration:hh\\:mm\\:ss}",
            $"Files scanned:   {scan.FilesScanned:N0}",
            $"Files skipped:   {scan.FilesSkipped:N0}",
            $"Threats found:   {scan.ThreatsFound}",
            "",
            "Scanned locations:"
        };
        lines.AddRange(scan.Targets.Select(t => "  • " + t));
        lines.Add("");

        if (scan.Detections.Count == 0)
        {
            lines.Add("RESULT: No threats found. Your PC is clean.");
        }
        else
        {
            lines.Add($"THREATS ({scan.Detections.Count})");
            lines.Add(new string('-', 70));
            var n = 1;
            foreach (var d in scan.Detections.OrderByDescending(d => d.Level))
            {
                lines.Add($"{n++}. [{d.Level.ToString().ToUpperInvariant()}] {d.ThreatName}");
                lines.Add($"   File:    {d.DisplayPath}");
                lines.Add($"   Method:  {d.Source}");
                lines.Add($"   Details: {d.Details}");
                if (d.Sha256 != null) lines.Add($"   SHA-256: {d.Sha256}");
                lines.Add($"   Action:  {d.ActionTaken}");
                lines.Add("");
            }
        }

        lines.Add(new string('=', 70));
        lines.Add($"Report created {DateTime.Now:dd MMM yyyy, hh:mm tt} by Kavach Antivirus");
        return lines;
    }

    private static string BuildCsv(ScanSummary scan)
    {
        static string Q(string? s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";
        var sb = new StringBuilder();
        sb.AppendLine("Level,Threat,File,Inside archive,Method,Details,SHA-256,Action,Found at");
        foreach (var d in scan.Detections.OrderByDescending(d => d.Level))
        {
            sb.AppendLine(string.Join(",",
                Q(d.Level.ToString()), Q(d.ThreatName), Q(d.FilePath), Q(d.InnerPath), Q(d.Source.ToString()),
                Q(d.Details), Q(d.Sha256), Q(d.ActionTaken), Q(d.FoundAt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))));
        }
        return sb.ToString();
    }
}

/// <summary>Tiny PDF writer (text only, A4 pages, built-in Courier font). No extra library needed.</summary>
public static class SimplePdf
{
    private const int LinesPerPage = 60;
    private const int MaxChars = 95;

    public static byte[] Create(string title, IEnumerable<string> rawLines)
    {
        // Wrap long lines
        var lines = new List<string>();
        foreach (var raw in rawLines)
        {
            var line = ToLatin(raw);
            if (line.Length == 0) { lines.Add(""); continue; }
            while (line.Length > MaxChars)
            {
                lines.Add(line[..MaxChars]);
                line = "     " + line[MaxChars..];
            }
            lines.Add(line);
        }

        var pages = new List<List<string>>();
        for (var i = 0; i < lines.Count; i += LinesPerPage) pages.Add(lines.Skip(i).Take(LinesPerPage).ToList());
        if (pages.Count == 0) pages.Add(new List<string>());

        var objects = new List<string>();
        // 1 = catalog, 2 = pages, 3 = font, then for each page: page object + content stream
        var pageIds = new List<int>();
        var nextId = 4;
        var pageObjects = new List<(int PageId, int ContentId, string Content)>();
        for (var p = 0; p < pages.Count; p++)
        {
            var content = BuildContent(pages[p], title, p + 1, pages.Count);
            pageObjects.Add((nextId, nextId + 1, content));
            pageIds.Add(nextId);
            nextId += 2;
        }

        var sb = new StringBuilder();
        var offsets = new SortedDictionary<int, int>();
        var output = new MemoryStream();
        void Write(string s)
        {
            var bytes = Encoding.Latin1.GetBytes(s);
            output.Write(bytes, 0, bytes.Length);
        }

        Write("%PDF-1.4\n%âãÏÓ\n");

        offsets[1] = (int)output.Position;
        Write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        offsets[2] = (int)output.Position;
        Write($"2 0 obj\n<< /Type /Pages /Kids [{string.Join(" ", pageIds.Select(id => id + " 0 R"))}] /Count {pageIds.Count} >>\nendobj\n");

        offsets[3] = (int)output.Position;
        Write("3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\nendobj\n");

        foreach (var (pageId, contentId, content) in pageObjects)
        {
            offsets[pageId] = (int)output.Position;
            Write($"{pageId} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] " +
                  $"/Resources << /Font << /F1 3 0 R >> >> /Contents {contentId} 0 R >>\nendobj\n");

            var contentBytes = Encoding.Latin1.GetBytes(content);
            offsets[contentId] = (int)output.Position;
            Write($"{contentId} 0 obj\n<< /Length {contentBytes.Length} >>\nstream\n");
            output.Write(contentBytes, 0, contentBytes.Length);
            Write("\nendstream\nendobj\n");
        }

        var xref = (int)output.Position;
        Write($"xref\n0 {nextId}\n0000000000 65535 f \n");
        for (var id = 1; id < nextId; id++) Write($"{offsets[id]:D10} 00000 n \n");
        Write($"trailer\n<< /Size {nextId} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        return output.ToArray();
    }

    private static string BuildContent(List<string> lines, string title, int page, int pageCount)
    {
        var sb = new StringBuilder();
        sb.Append("BT\n/F1 13 Tf\n40 800 Td\n(").Append(Escape(ToLatin(title))).Append(") Tj\nET\n");
        sb.Append("BT\n/F1 8 Tf\n480 800 Td\n(").Append(Escape($"Page {page} of {pageCount}")).Append(") Tj\nET\n");
        sb.Append("BT\n/F1 9 Tf\n11 TL\n40 775 Td\n");
        foreach (var line in lines)
        {
            sb.Append('(').Append(Escape(line)).Append(") Tj T*\n");
        }
        sb.Append("ET\n");
        return sb.ToString();
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");

    /// <summary>Replace characters the built-in PDF font cannot show.</summary>
    private static string ToLatin(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            sb.Append(c switch
            {
                '—' or '–' => '-',
                '•' => '*',
                '›' => '>',
                '→' => '>',
                '“' or '”' => '"',
                '‘' or '’' => '\'',
                _ => c <= 255 ? c : '?'
            });
        }
        return sb.ToString();
    }
}
