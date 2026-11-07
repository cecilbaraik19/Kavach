using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Kavach.Core.Infrastructure;
using Microsoft.Win32;

namespace Kavach.App.Pages;

/// <summary>Past scans and their detections.</summary>
public partial class HistoryPage : UserControl, IKavachPage
{
    public HistoryPage()
    {
        InitializeComponent();
        AppServices.Context.History.Changed += () => AppServices.Run(() => { if (IsVisible) Refresh(); });
    }

    public void OnNavigatedTo(object? parameter) => Refresh();

    private void Refresh()
    {
        var selectedId = (ScanList.SelectedItem as HistoryRow)?.Scan.Id;
        var rows = AppServices.Context.History.All().Select(s => new HistoryRow(s)).ToList();
        ScanList.ItemsSource = rows;
        ScanList.SelectedItem = rows.FirstOrDefault(r => r.Scan.Id == selectedId) ?? rows.FirstOrDefault();
        if (rows.Count == 0) ShowDetail(null);
    }

    private void ScanList_SelectionChanged(object sender, SelectionChangedEventArgs e) => ShowDetail(ScanList.SelectedItem as HistoryRow);

    private void ShowDetail(HistoryRow? row)
    {
        ExportButton.IsEnabled = row != null;
        DetailNumbers.Visibility = row == null ? Visibility.Collapsed : Visibility.Visible;
        if (row == null)
        {
            DetailTitle.Text = "No scans yet";
            DetailSub.Text = "Run a scan and its results will be kept here.";
            DTargets.Text = "";
            DDetections.ItemsSource = null;
            DClean.Visibility = Visibility.Collapsed;
            return;
        }

        var s = row.Scan;
        DetailTitle.Text = $"{row.Title} — {row.Result}";
        DetailSub.Text = $"{s.Started:dddd, dd MMMM yyyy, hh:mm tt} • {s.Status}" + (s.Error != null ? " • " + s.Error : "");
        DScanned.Text = s.FilesScanned.ToString("N0");
        DSkipped.Text = s.FilesSkipped.ToString("N0");
        DThreats.Text = s.ThreatsFound.ToString("N0");
        DDuration.Text = Ui.Duration(s.Duration);
        DTargets.Text = "Locations: " + string.Join("  •  ", s.Targets);
        DDetections.ItemsSource = s.Detections.Select(d => new DetectionRow(d)).ToList();
        DClean.Visibility = s.Detections.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (ScanList.SelectedItem is not HistoryRow row) return;
        var dialog = new SaveFileDialog
        {
            Title = "Save scan report",
            FileName = $"Kavach-{row.Scan.Type}-scan-{row.Scan.Started:yyyyMMdd-HHmm}",
            Filter = "PDF report (*.pdf)|*.pdf|Text report (*.txt)|*.txt|Spreadsheet (*.csv)|*.csv"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            ReportExporter.Export(row.Scan, dialog.FileName, ReportExporter.FormatFromExtension(dialog.FileName));
            AppServices.Toast("Report saved");
            WindowsIntegration.OpenInExplorer(dialog.FileName);
        }
        catch (Exception ex)
        {
            AppServices.Toast("Could not save: " + ex.Message, isError: true);
        }
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm.Ask("Clear scan history?", "All past scan records will be removed. Quarantined files are not affected.")) return;
        AppServices.Context.History.Clear();
        Refresh();
    }
}
