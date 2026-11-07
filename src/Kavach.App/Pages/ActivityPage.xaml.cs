using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Kavach.Core;
using Microsoft.Win32;

namespace Kavach.App.Pages;

/// <summary>Activity log viewer.</summary>
public partial class ActivityPage : UserControl, IKavachPage
{
    private string _filter = "All";

    public ActivityPage()
    {
        InitializeComponent();
    }

    public void OnNavigatedTo(object? parameter) => Refresh();

    private void Refresh()
    {
        var entries = AppServices.Context.Log.ReadRecent(2000);
        if (_filter != "All" && Enum.TryParse<LogLevel>(_filter, out var level)) entries = entries.Where(e => e.Level == level).ToList();
        LogList.ItemsSource = entries.Select(e => new LogRow(e)).ToList();
        CountText.Text = $"{entries.Count:N0} entries";
    }

    private void Filter_Checked(object sender, RoutedEventArgs e)
    {
        _filter = (sender as FrameworkElement)?.Tag as string ?? "All";
        if (IsLoaded) Refresh();
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => Refresh();

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm.Ask("Clear the activity log?", "All log entries will be removed.")) return;
        AppServices.Context.Log.Clear();
        AppServices.Context.Log.Info("Log", "Activity log cleared by user");
        Refresh();
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { FileName = $"Kavach-activity-{DateTime.Now:yyyyMMdd-HHmm}.txt", Filter = "Text file (*.txt)|*.txt" };
        if (dialog.ShowDialog() != true) return;
        var lines = AppServices.Context.Log.ReadRecent(100_000)
            .Select(l => $"{l.Time:yyyy-MM-dd HH:mm:ss}  {l.Level,-8} {l.Category,-16} {l.Message}");
        File.WriteAllLines(dialog.FileName, lines);
        AppServices.Toast("Activity log exported");
    }
}
