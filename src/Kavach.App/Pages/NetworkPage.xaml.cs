using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Kavach.App.Services;
using Kavach.Core;
using Kavach.Core.Response;
using Kavach.Core.SystemChecks;

namespace Kavach.App.Pages;

/// <summary>Live list of network connections and the programs behind them.</summary>
public partial class NetworkPage : UserControl, IKavachPage
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(3) };
    private List<ConnectionInfo> _all = new();
    private bool _loading;

    public NetworkPage()
    {
        InitializeComponent();
        _timer.Tick += (_, _) => Load();
        Unloaded += (_, _) => _timer.Stop();
        Loaded += (_, _) => { if (AutoRefresh.IsChecked == true) _timer.Start(); };
    }

    public void OnNavigatedTo(object? parameter)
    {
        Load();
        if (AutoRefresh.IsChecked == true) _timer.Start();
    }

    private async void Load()
    {
        if (_loading) return;
        _loading = true;
        try
        {
            _all = await Task.Run(() => NetworkMonitor.GetConnections());
            NumTotal.Text = _all.Count.ToString("N0");
            NumEstablished.Text = _all.Count(c => c.State == "Established").ToString("N0");
            NumListening.Text = _all.Count(c => c.State == "Listening").ToString("N0");
            var flagged = _all.Count(c => c.IsFlagged);
            NumFlagged.Text = flagged.ToString("N0");
            NumFlagged.SetResourceReference(TextBlock.ForegroundProperty, flagged > 0 ? "DangerBrush" : "TextBrush");
            ApplyFilter();
        }
        catch (Exception ex)
        {
            AppServices.Toast("Could not read connections: " + ex.Message, isError: true);
        }
        finally
        {
            _loading = false;
        }
    }

    private void ApplyFilter()
    {
        var text = Filter.Text.Trim();
        FilterHint.Visibility = text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;

        IEnumerable<ConnectionInfo> rows = _all;
        if (HideListening.IsChecked == true) rows = rows.Where(c => c.State != "Listening");
        if (HideLocal.IsChecked == true)
            rows = rows.Where(c => c.IsFlagged || !(c.RemoteAddress.StartsWith("127.") || c.RemoteAddress == "::1" ||
                                                    (c.State != "Listening" && (c.RemoteAddress is "0.0.0.0" or "::"))));
        if (text.Length > 0)
        {
            rows = rows.Where(c =>
                c.ProcessName.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                c.Remote.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                c.Local.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                c.State.Contains(text, StringComparison.OrdinalIgnoreCase) ||
                c.ProcessId.ToString() == text);
        }
        ConnList.ItemsSource = rows.ToList();
    }

    private void Filter_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();
    private void Filter_Click(object sender, RoutedEventArgs e) => ApplyFilter();
    private void Refresh_Click(object sender, RoutedEventArgs e) => Load();

    private void AutoRefresh_Click(object sender, RoutedEventArgs e)
    {
        if (AutoRefresh.IsChecked == true) _timer.Start();
        else _timer.Stop();
    }

    private void Kill_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not ConnectionInfo c) return;
        if (c.ProcessId <= 4)
        {
            AppServices.Toast("Windows system processes cannot be stopped", isError: true);
            return;
        }
        if (!Confirm.Ask("Stop program?", $"Stop {c.ProcessName} (PID {c.ProcessId})?\n\n{c.ProcessPath}\n\nUnsaved work in that program will be lost.")) return;

        if (ProcessKiller.Kill(c.ProcessId))
        {
            AppServices.Context.Log.Warning("Network", $"User stopped {c.ProcessName} (PID {c.ProcessId}) connected to {c.Remote}");
            AppServices.Toast($"{c.ProcessName} stopped");
            if (c.IsFlagged && c.ProcessPath != null &&
                Confirm.Ask("Quarantine the program?", $"{c.ProcessName} was flagged: {c.Reason}\n\nMove its program file to quarantine as well?"))
            {
                var result = AppServices.Context.Quarantine.Quarantine(c.ProcessPath, "Suspicious.NetworkActivity", c.Risk);
                AppServices.Toast(result.Message, !result.Success);
            }
            Load();
        }
        else
        {
            AppServices.Toast("Could not stop it — try running Kavach as administrator", isError: true);
        }
    }
}
