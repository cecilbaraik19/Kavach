using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Kavach.Core;
using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;
using Kavach.Core.Response;
using Kavach.Core.Scanning;
using Microsoft.Win32;

namespace Kavach.App.Pages;

/// <summary>Request to open the scanner: start this type (and paths for Custom) right away.</summary>
public sealed record ScanRequest(ScanType Type, string[]? Paths);

/// <summary>Malware Scanner page: choose a scan, watch progress, act on threats.</summary>
public partial class ScanPage : UserControl, IKavachPage
{
    private readonly ObservableCollection<DetectionRow> _rows = new();
    private ScanJob? _job;

    public ScanPage()
    {
        InitializeComponent();
        ResultList.ItemsSource = _rows;
        AppServices.ActiveScanChanged += () => Attach(AppServices.ActiveScan);
    }

    public void OnNavigatedTo(object? parameter)
    {
        if (parameter is ScanRequest request)
        {
            SelectType(request.Type);
            if (request.Paths is { Length: > 0 })
            {
                CustomPath.Text = string.Join(";", request.Paths);
                Start(ScanType.Custom, request.Paths);
            }
            else if (request.Type != ScanType.Custom)
            {
                Start(request.Type, null);
            }
            else
            {
                CustomPath.Focus();
            }
            return;
        }
        Attach(AppServices.ActiveScan);
    }

    // ───────────────────────── Choosing ─────────────────────────

    private ScanType SelectedType =>
        FullRadio.IsChecked == true ? ScanType.Full :
        CustomRadio.IsChecked == true ? ScanType.Custom :
        ProcessRadio.IsChecked == true ? ScanType.Processes : ScanType.Quick;

    private void SelectType(ScanType type)
    {
        switch (type)
        {
            case ScanType.Full: FullRadio.IsChecked = true; break;
            case ScanType.Custom: CustomRadio.IsChecked = true; break;
            case ScanType.Processes: ProcessRadio.IsChecked = true; break;
            default: QuickRadio.IsChecked = true; break;
        }
    }

    private void Type_Checked(object sender, RoutedEventArgs e)
    {
        if (CustomPanel == null) return; // still loading
        CustomPanel.Visibility = CustomRadio.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ChooseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose files to scan", Multiselect = true };
        if (dialog.ShowDialog() == true) CustomPath.Text = string.Join(";", dialog.FileNames);
    }

    private void ChooseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose a folder or drive to scan", Multiselect = true };
        if (dialog.ShowDialog() == true) CustomPath.Text = string.Join(";", dialog.FolderNames);
    }

    private void Page_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
        {
            SelectType(ScanType.Custom);
            CustomPath.Text = string.Join(";", paths);
            Start(ScanType.Custom, paths);
        }
    }

    // ───────────────────────── Running ─────────────────────────

    private void Start_Click(object sender, RoutedEventArgs e)
    {
        if (_job?.IsRunning == true) return;

        var type = SelectedType;
        string[]? paths = null;
        if (type == ScanType.Custom)
        {
            paths = CustomPath.Text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(p => p.Trim('"'))
                .Where(p => File.Exists(p) || Directory.Exists(p))
                .ToArray();
            if (paths.Length == 0)
            {
                AppServices.Toast("Choose a file or folder that exists first", isError: true);
                return;
            }
        }
        Start(type, paths);
    }

    private void Start(ScanType type, string[]? paths)
    {
        if (AppServices.ActiveScan?.IsRunning == true)
        {
            Attach(AppServices.ActiveScan);
            AppServices.Toast("A scan is already running — wait for it to finish or cancel it");
            return;
        }
        var job = AppServices.StartScan(type, paths, useCache: FreshScan.IsChecked != true);
        Attach(job);
    }

    private void Attach(ScanJob? job)
    {
        if (job == null)
        {
            return;
        }

        if (!ReferenceEquals(job, _job))
        {
            if (_job != null)
            {
                _job.ProgressChanged -= OnProgress;
                _job.ThreatFound -= OnThreat;
            }
            _job = job;
            _rows.Clear();
            foreach (var d in job.Summary.Detections.ToList()) _rows.Add(new DetectionRow(d));
            job.ProgressChanged += OnProgress;
            job.ThreatFound += OnThreat;
        }

        ProgressCard.Visibility = Visibility.Visible;
        UpdateProgressView(job.CurrentProgress);
    }

    private void OnProgress(ScanProgress p) => AppServices.Run(() => UpdateProgressView(p));

    private void OnThreat(Detection d) => AppServices.Run(() =>
    {
        _rows.Add(new DetectionRow(d));
        UpdateResultsVisibility();
    });

    private void UpdateProgressView(ScanProgress p)
    {
        var job = _job;
        if (job == null) return;

        var running = job.IsRunning;
        NumScanned.Text = p.FilesScanned.ToString("N0");
        NumSkipped.Text = p.FilesSkipped.ToString("N0");
        NumThreats.Text = p.ThreatsFound.ToString("N0");
        NumTime.Text = Ui.Duration(p.Elapsed);
        CurrentFile.Text = running ? p.CurrentFile : "";

        StartButton.IsEnabled = !running;
        StartButtonText.Text = running ? "Scanning…" : "Start scan";
        PauseButton.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        TypePanel.IsEnabled = !running;

        if (running)
        {
            ProgressTitle.Text = job.IsPaused ? "Scan paused" : $"{Ui.ScanTypeName(job.Type)} in progress…";
            ProgressSubtitle.Text = p.DiscoveryFinished
                ? $"{p.FilesScanned + p.FilesSkipped:N0} of {p.FilesDiscovered:N0} files checked"
                : $"Finding files… {p.FilesDiscovered:N0} so far";
            Bar.IsIndeterminate = p.Percent == null;
            if (p.Percent != null) Bar.Value = p.Percent.Value;
            PauseText.Text = job.IsPaused ? "Resume" : "Pause";
            PauseIcon.Text = job.IsPaused ? "" : "";
            ProgressIcon.Text = "";
            ProgressBubble.SetResourceReference(Border.BackgroundProperty, "AccentSoftBrush");
            ProgressIcon.SetResourceReference(TextBlock.ForegroundProperty, "AccentTextBrush");
            CleanCard.Visibility = Visibility.Collapsed;
        }
        else
        {
            var s = job.Summary;
            Bar.IsIndeterminate = false;
            Bar.Value = 100;
            ProgressTitle.Text = s.Status switch
            {
                ScanStatus.Cancelled => "Scan cancelled",
                ScanStatus.Failed => "Scan stopped with an error",
                _ => s.ThreatsFound > 0 ? $"Scan complete — {s.ThreatsFound} threat(s) found" : "Scan complete — your PC is clean"
            };
            ProgressSubtitle.Text = $"{Ui.ScanTypeName(s.Type)} • finished {s.Finished:hh:mm tt} • {s.FilesScanned:N0} scanned, {s.FilesSkipped:N0} skipped" +
                                    (s.Error != null ? " • " + s.Error : "");
            var threats = s.ThreatsFound > 0;
            ProgressIcon.Text = threats ? "" : "";
            ProgressBubble.SetResourceReference(Border.BackgroundProperty, threats ? "DangerSoftBrush" : "SuccessSoftBrush");
            ProgressIcon.SetResourceReference(TextBlock.ForegroundProperty, threats ? "DangerBrush" : "SuccessBrush");

            CleanCard.Visibility = !threats && s.Status == ScanStatus.Completed ? Visibility.Visible : Visibility.Collapsed;
            CleanText.Text = $"Kavach checked {s.FilesScanned:N0} items in {Ui.Duration(s.Duration)}. Nothing harmful was found.";
        }

        ExportButton.Visibility = running ? Visibility.Collapsed : Visibility.Visible;
        UpdateResultsVisibility();
    }

    private void UpdateResultsVisibility()
    {
        ResultsPanel.Visibility = _rows.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        var files = _rows.Select(r => r.D.FilePath + "|" + r.D.InnerPath).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        ResultCount.Text = files == _rows.Count ? $"{files}" : $"{files} files • {_rows.Count} detections";
    }

    private void Pause_Click(object sender, RoutedEventArgs e)
    {
        if (_job == null) return;
        if (_job.IsPaused) _job.Resume();
        else _job.Pause();
        UpdateProgressView(_job.CurrentProgress);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _job?.Cancel();

    // ───────────────────────── Acting on threats ─────────────────────────

    private static DetectionRow? RowOf(object sender) => (sender as FrameworkElement)?.Tag as DetectionRow;

    private void Quarantine_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is { } row) QuarantineRows(new[] { row });
    }

    private void QuarantineSelected_Click(object sender, RoutedEventArgs e)
    {
        var rows = _rows.Where(r => r.IsSelected && !r.IsHandled).ToList();
        if (rows.Count == 0)
        {
            AppServices.Toast("Select at least one threat first", isError: true);
            return;
        }
        QuarantineRows(rows);
    }

    private void QuarantineRows(System.Collections.Generic.IEnumerable<DetectionRow> rows)
    {
        var ctx = AppServices.Context;
        var done = 0;
        var failed = 0;
        string? lastError = null;

        foreach (var group in rows.GroupBy(r => r.D.FilePath, StringComparer.OrdinalIgnoreCase))
        {
            var first = group.OrderByDescending(r => r.Level).First();

            if (first.D.Source == DetectionSource.Hosts)
            {
                if (HostsFileCheckerReset(out var msg))
                {
                    foreach (var r in group) MarkAll(r.D.FilePath, "Hosts file reset");
                    done++;
                }
                else
                {
                    failed++;
                    lastError = msg;
                }
                continue;
            }

            if (!File.Exists(first.D.FilePath))
            {
                MarkAll(first.D.FilePath, "Already removed");
                continue;
            }

            if (first.IsRunning) ProcessKiller.KillByPath(first.D.FilePath);
            var result = ctx.Quarantine.Quarantine(first.D.FilePath, first.ThreatName, first.Level);
            if (result.Success)
            {
                MarkAll(first.D.FilePath, "Quarantined");
                done++;
            }
            else
            {
                failed++;
                lastError = result.Message;
            }
        }

        if (failed == 0) AppServices.Toast(done == 1 ? "Threat moved to quarantine" : $"{done} threats moved to quarantine");
        else AppServices.Toast($"{done} quarantined, {failed} failed: {lastError}", isError: true);
        AppServices.RaiseStatus();
    }

    private static bool HostsFileCheckerReset(out string message) =>
        Kavach.Core.SystemChecks.HostsFileChecker.Reset(out message);

    private void MarkAll(string path, string action)
    {
        foreach (var r in _rows.Where(r => string.Equals(r.D.FilePath, path, StringComparison.OrdinalIgnoreCase)))
        {
            r.Action = action;
            AppServices.Context.History.UpdateDetectionAction(r.D.Id, action);
        }
    }

    private void Allow_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is { } row) AllowRows(new[] { row });
    }

    private void AllowSelected_Click(object sender, RoutedEventArgs e)
    {
        var rows = _rows.Where(r => r.IsSelected && !r.IsHandled).ToList();
        if (rows.Count == 0) return;
        AllowRows(rows);
    }

    private void AllowRows(System.Collections.Generic.IList<DetectionRow> rows)
    {
        if (!Confirm.Ask("Allow these files?",
                $"Kavach will trust {rows.Select(r => r.D.FilePath).Distinct().Count()} file(s) and stop flagging them.\n\nOnly do this if you are sure they are safe.")) return;

        AppServices.Context.Settings.Update(s =>
        {
            foreach (var r in rows)
            {
                var hash = r.D.Sha256 ?? HashDatabase.ComputeSha256(r.D.FilePath);
                if (hash != null && string.IsNullOrEmpty(r.D.InnerPath))
                {
                    if (!s.AllowedHashes.Contains(hash, StringComparer.OrdinalIgnoreCase)) s.AllowedHashes.Add(hash);
                }
                else if (!s.ExcludedPaths.Contains(r.D.FilePath, StringComparer.OrdinalIgnoreCase))
                {
                    s.ExcludedPaths.Add(r.D.FilePath);
                }
            }
        });
        foreach (var r in rows) MarkAll(r.D.FilePath, "Allowed by you");
        AppServices.Context.Log.Warning("Allowlist", $"User allowed {rows.Count} detection(s)");
        AppServices.Toast("Added to the allowlist");
    }

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        var select = _rows.Any(r => !r.IsSelected);
        foreach (var r in _rows) r.IsSelected = select;
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is { } row) WindowsIntegration.OpenInExplorer(row.D.FilePath);
    }

    private async void VirusTotal_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is not { } row) return;
        var hash = row.D.Sha256 ?? HashDatabase.ComputeSha256(row.D.FilePath);
        if (hash == null)
        {
            AppServices.Toast("Cannot read the file to compute its fingerprint", isError: true);
            return;
        }
        AppServices.Toast("Asking VirusTotal…");
        var report = await VirusTotalClient.LookupAsync(hash, AppServices.Context.Settings.Current.VirusTotalApiKey);
        ShowVtReport(report, row.FileName);
    }

    private async void VtFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a file to check on VirusTotal" };
        if (dialog.ShowDialog() != true) return;
        VtText.Text = "Computing fingerprint and asking VirusTotal…";
        var path = dialog.FileName;
        var hash = await Task.Run(() => HashDatabase.ComputeSha256(path));
        if (hash == null)
        {
            VtText.Text = "Could not read that file.";
            return;
        }
        var report = await VirusTotalClient.LookupAsync(hash, AppServices.Context.Settings.Current.VirusTotalApiKey);
        VtText.Text = $"{Path.GetFileName(path)}: {report.Summary}";
        ShowVtReport(report, Path.GetFileName(path));
    }

    private static void ShowVtReport(VirusTotalReport report, string fileName)
    {
        if (report.Error != null)
        {
            AppServices.Toast(report.Error, isError: true);
            return;
        }
        if (Confirm.Ask("VirusTotal result — " + fileName, report.Summary + "\n\nOpen the full report in your browser?"))
            WindowsIntegration.OpenUrl(report.Link);
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_job == null) return;
        var dialog = new SaveFileDialog
        {
            Title = "Save scan report",
            FileName = $"Kavach-{_job.Type}-scan-{_job.Summary.Started:yyyyMMdd-HHmm}",
            Filter = "PDF report (*.pdf)|*.pdf|Text report (*.txt)|*.txt|Spreadsheet (*.csv)|*.csv"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            ReportExporter.Export(_job.Summary, dialog.FileName, ReportExporter.FormatFromExtension(dialog.FileName));
            AppServices.Toast("Report saved");
            WindowsIntegration.OpenInExplorer(dialog.FileName);
        }
        catch (Exception ex)
        {
            AppServices.Toast("Could not save the report: " + ex.Message, isError: true);
        }
    }
}
