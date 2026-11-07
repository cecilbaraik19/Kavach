using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Kavach.App.Services;
using Kavach.Core;
using Kavach.Core.Infrastructure;

namespace Kavach.App.Pages;

/// <summary>Dashboard: protection status, scan tiles, numbers, modules and recent alerts.</summary>
public partial class HomePage : UserControl, IKavachPage
{
    private sealed record ModuleState(string Name, string State, Brush Brush);

    private ProtectionLevel _level;

    public HomePage()
    {
        InitializeComponent();
        AppServices.StatusChanged += Refresh;
        AppServices.ActiveScanChanged += Refresh;
        AdminNote.Visibility = AppServices.IsAdmin ? Visibility.Collapsed : Visibility.Visible;
    }

    public void OnNavigatedTo(object? parameter) => Refresh();

    private void Refresh()
    {
        var ctx = AppServices.Context;
        var settings = ctx.Settings.Current;
        var status = AppServices.GetStatus();
        _level = status.Level;

        HeroTitle.Text = status.Title;
        HeroMessage.Text = status.Message;
        var (fg, bg, glyph) = status.Level switch
        {
            ProtectionLevel.Protected => ("SuccessBrush", "SuccessSoftBrush", ""),
            ProtectionLevel.Attention => ("WarningBrush", "WarningSoftBrush", ""),
            _ => ("DangerBrush", "DangerSoftBrush", "")
        };
        HeroBubble.SetResourceReference(Border.BackgroundProperty, bg);
        HeroIcon.SetResourceReference(TextBlock.ForegroundProperty, fg);
        HeroIcon.Text = glyph;

        var scanning = AppServices.ActiveScan?.IsRunning == true;
        HeroActionText.Text = scanning ? "View running scan"
            : !settings.RealTimeProtection ? "Turn protection on"
            : status.Title.StartsWith("Threats") ? "Review threats"
            : "Quick scan";

        // Numbers
        var quarantine = ctx.Quarantine.List();
        StatBlocked.Text = settings.ThreatsBlockedTotal.ToString("N0");
        StatQuarantine.Text = quarantine.Count.ToString("N0");
        StatQuarantineSize.Text = Ui.FormatBytes(quarantine.Sum(q => q.Size));

        var last = ctx.History.All().FirstOrDefault(h => h.Type != ScanType.RealTime);
        StatLastScan.Text = last == null ? "Never" : Ui.TimeAgo(last.Started);
        StatLastScanType.Text = last == null ? "Run a Quick scan" : $"{Ui.ScanTypeName(last.Type)} • {(last.ThreatsFound == 0 ? "clean" : last.ThreatsFound + " threat(s)")}";

        StatSignatures.Text = (ctx.Hashes.Count + ctx.Rules.Rules.Count).ToString("N0");
        StatSignaturesInfo.Text = $"{ctx.Hashes.Count:N0} hashes • {ctx.Rules.Rules.Count} rules • v{ctx.Hashes.VersionInfo.Version}";

        // Modules
        var on = Ui.Res("SuccessBrush");
        var off = Ui.Res("DangerBrush");
        var muted = Ui.Res("MutedBrush");
        var rt = settings.RealTimeProtection;
        ModuleList.ItemsSource = new List<ModuleState>
        {
            new("Real-time file protection", rt ? "On" : "Off", rt ? on : off),
            new("Download warnings", rt && settings.DownloadWarnings ? "On" : "Off", rt && settings.DownloadWarnings ? on : muted),
            new("Ransomware protection", rt && settings.RansomwareProtection ? "On" : "Off", rt && settings.RansomwareProtection ? on : off),
            new("Script memory scanning", rt && settings.ScriptMemoryProtection ? "On" : "Off", rt && settings.ScriptMemoryProtection ? on : muted),
            new("USB auto-scan", settings.UsbAutoScan ? "On" : "Off", settings.UsbAutoScan ? on : muted),
            new("Self-protection", settings.SelfProtection && AppServices.ServiceConnected ? "On" : settings.SelfProtection ? "Needs service" : "Off",
                settings.SelfProtection && AppServices.ServiceConnected ? on : muted),
            new("Scheduled scans", settings.Schedules.Any(s => s.Enabled) ? $"{settings.Schedules.Count(s => s.Enabled)} active" : "None",
                settings.Schedules.Any(s => s.Enabled) ? on : muted)
        };
        HostText.Text = "Running in: " + AppServices.ProtectionHostDescription;

        // Alerts
        var alerts = AppServices.RecentEvents.Take(5).Select(e => new EventRow(e)).ToList();
        AlertList.ItemsSource = alerts;
        NoAlerts.Visibility = alerts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private MainWindow? Main => Window.GetWindow(this) as MainWindow;

    private void HeroAction_Click(object sender, RoutedEventArgs e)
    {
        var settings = AppServices.Context.Settings;
        if (AppServices.ActiveScan?.IsRunning == true)
        {
            Main?.Navigate("scan");
        }
        else if (!settings.Current.RealTimeProtection)
        {
            settings.Update(s => s.RealTimeProtection = true);
            AppServices.Toast("Real-time protection is on");
        }
        else if (_level == ProtectionLevel.AtRisk)
        {
            Main?.Navigate("history");
        }
        else
        {
            Main?.StartScan(ScanType.Quick);
        }
    }

    private void Tile_Click(object sender, RoutedEventArgs e)
    {
        var tag = (sender as Button)?.Tag as string;
        switch (tag)
        {
            case "quick": Main?.StartScan(ScanType.Quick); break;
            case "full": Main?.StartScan(ScanType.Full); break;
            default: Main?.Navigate("scan", new ScanRequest(ScanType.Custom, null)); break;
        }
    }

    private void ManageProtection_Click(object sender, RoutedEventArgs e) => Main?.Navigate("realtime");
    private void Updates_Click(object sender, RoutedEventArgs e) => Main?.Navigate("updates");

    private void Admin_Click(object sender, RoutedEventArgs e)
    {
        if (WindowsIntegration.RestartAsAdmin()) App.Current.ExitWithoutPrompt();
    }
}
