using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Kavach.Core;
using Kavach.Core.Infrastructure;
using Kavach.Core.SystemChecks;

namespace Kavach.App.Pages;

/// <summary>Startup items, Winlogon/IFEO hijacks and the hosts file.</summary>
public partial class SystemCheckPage : UserControl, IKavachPage
{
    private List<StartupRow> _all = new();
    private bool _running;
    private bool _checkedOnce;

    public SystemCheckPage()
    {
        InitializeComponent();
    }

    public void OnNavigatedTo(object? parameter)
    {
        RefreshDisabled();
        if (!_checkedOnce) Run();
    }

    private void Run_Click(object sender, RoutedEventArgs e) => Run();

    private async void Run()
    {
        if (_running) return;
        _running = true;
        _checkedOnce = true;
        RunButton.IsEnabled = false;
        RunText.Text = "Checking…";
        EmptyText.Text = "Checking startup items and scanning the programs behind them…";
        EmptyText.Visibility = Visibility.Visible;

        try
        {
            var engine = AppServices.Context.Engine;
            var (items, hosts) = await Task.Run(() => (StartupScanner.Scan(engine, CancellationToken.None), HostsFileChecker.Check()));

            _all = items.OrderByDescending(i => i.Risk).ThenBy(i => i.Name).Select(i => new StartupRow(i)).ToList();
            NumItems.Text = _all.Count.ToString("N0");
            var risky = _all.Count(r => r.Level >= ThreatLevel.Medium);
            NumRisky.Text = risky.ToString("N0");
            NumRisky.SetResourceReference(TextBlock.ForegroundProperty, risky > 0 ? "DangerBrush" : "TextBrush");

            HostsState.Text = !hosts.Exists ? "Missing" : hosts.IsClean ? "Clean" : "Changed";
            HostsState.SetResourceReference(TextBlock.ForegroundProperty, hosts.IsClean ? "SuccessBrush" : "DangerBrush");
            HostsInfo.Text = $"{hosts.Entries.Count} custom entries";
            HostsCard.Visibility = hosts.IsClean ? Visibility.Collapsed : Visibility.Visible;
            HostsDetails.Text = string.Join("\n", hosts.Detections.Take(6).Select(d => "• " + d.Details));

            ApplyFilter();
            var summary = $"System check: {_all.Count} startup items, {risky} need attention, hosts file {(hosts.IsClean ? "clean" : "changed")}";
            if (risky > 0 || !hosts.IsClean) AppServices.Context.Log.Threat("System check", summary);
            else AppServices.Context.Log.Info("System check", summary);
        }
        catch (Exception ex)
        {
            AppServices.Toast("System check failed: " + ex.Message, isError: true);
        }
        finally
        {
            _running = false;
            RunButton.IsEnabled = true;
            RunText.Text = "Check again";
        }
    }

    private void ApplyFilter()
    {
        var rows = OnlyRisky.IsChecked == true ? _all.Where(r => r.Level >= ThreatLevel.Medium).ToList() : _all;
        ItemList.ItemsSource = rows;
        EmptyText.Text = OnlyRisky.IsChecked == true ? "Nothing suspicious starts with Windows." : "No startup items found.";
        EmptyText.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Filter_Click(object sender, RoutedEventArgs e) => ApplyFilter();

    private void RefreshDisabled()
    {
        var disabled = StartupScanner.ListDisabled().Select(d => new DisabledRow(d)).ToList();
        DisabledList.ItemsSource = disabled;
        NoDisabled.Visibility = disabled.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Disable_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not StartupRow row) return;
        if (!Confirm.Ask("Disable startup item?", $"\"{row.Name}\" will no longer start with Windows.\n\nYou can restore it later from this page.")) return;

        if (StartupScanner.Disable(row.Item, out var message))
        {
            AppServices.Context.Log.Warning("Startup", $"Disabled startup item {row.Name} ({row.Command})");
            _all.Remove(row);
            ApplyFilter();
            RefreshDisabled();
            AppServices.Toast(message);
        }
        else
        {
            AppServices.Toast(message, isError: true);
        }
    }

    private void Restore_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not DisabledRow row) return;
        if (StartupScanner.Restore(row.Entry.Id, out var message))
        {
            AppServices.Context.Log.Info("Startup", $"Restored startup item {row.Name}");
            RefreshDisabled();
            AppServices.Toast(message);
        }
        else
        {
            AppServices.Toast(message, isError: true);
        }
    }

    private void Folder_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is StartupRow row)
            WindowsIntegration.OpenInExplorer(row.Item.FilePath ?? StartupScanner.ExtractPath(row.Command) ?? "");
    }

    private void ResetHosts_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm.Ask("Reset hosts file?", "Kavach will back up your hosts file and replace it with the clean Windows default.")) return;
        if (HostsFileChecker.Reset(out var message))
        {
            AppServices.Context.Log.Warning("Hosts", message);
            AppServices.Toast("Hosts file reset to the Windows default");
            Run();
        }
        else
        {
            AppServices.Toast(message, isError: true);
        }
    }
}
