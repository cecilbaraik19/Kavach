using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Kavach.Core.Infrastructure;
using Kavach.Core.Protection;
using Microsoft.Win32;

namespace Kavach.App.Pages;

/// <summary>Real-time protection switches, watched folders and live alerts.</summary>
public partial class RealTimePage : UserControl, IKavachPage
{
    private bool _loading;

    public RealTimePage()
    {
        InitializeComponent();
        AppServices.StatusChanged += Refresh;
        AppServices.RecentEvents.CollectionChanged += (_, _) => RefreshEvents();
    }

    public void OnNavigatedTo(object? parameter) => Refresh();

    private static readonly (string Key, string Glyph, string Title, string Text)[] Features =
    {
        ("DownloadWarnings", "", "Download warnings", "Tells you when a new program lands in Downloads, and whether it is digitally signed."),
        ("AutoQuarantine", "", "Quarantine threats automatically", "Threats found by real-time protection are stopped and moved to quarantine without asking."),
        ("RansomwareProtection", "", "Ransomware protection", "Places hidden bait files in Documents, Desktop and Pictures and stops any program that encrypts them."),
        ("ScriptMemoryProtection", "\uE943", "Script memory scanning", "Checks PowerShell scripts as they run — even encoded ones that never touch the disk — and stops fileless attacks."),
        ("UsbAutoScan", "", "USB drive auto-scan", "Scans pen drives as soon as they are plugged in and blocks autorun worms."),
        ("SelfProtection", "", "Self-protection", "Stops normal programs from closing or tampering with the Kavach service. Needs the Kavach service.")
    };

    private void Refresh()
    {
        _loading = true;
        var s = AppServices.Context.Settings.Current;

        MasterState.Text = s.RealTimeProtection ? "ON" : "OFF";
        MasterState.SetResourceReference(TextBlock.ForegroundProperty, s.RealTimeProtection ? "SuccessBrush" : "DangerBrush");
        MasterBubble.SetResourceReference(Border.BackgroundProperty, s.RealTimeProtection ? "SuccessSoftBrush" : "DangerSoftBrush");
        MasterIcon.SetResourceReference(TextBlock.ForegroundProperty, s.RealTimeProtection ? "SuccessBrush" : "DangerBrush");
        MasterIcon.Text = s.RealTimeProtection ? "" : "";
        MasterText.Text = s.RealTimeProtection
            ? "Every new or changed file in watched folders is scanned the moment it is saved."
            : "Your PC is not being watched. New threats will not be stopped until you turn this back on.";
        MasterButtonText.Text = s.RealTimeProtection ? "TURN OFF" : "TURN ON";
        MasterButton.Style = (Style)FindResource(s.RealTimeProtection ? "SecondaryButton" : "PrimaryButton");
        HostText.Text = "Running in: " + AppServices.ProtectionHostDescription;

        FeatureList.Children.Clear();
        foreach (var f in Features) FeatureList.Children.Add(BuildFeatureRow(f.Key, f.Glyph, f.Title, f.Text, GetFeature(s, f.Key), s.RealTimeProtection || f.Key == "UsbAutoScan"));

        DefaultFolders.ItemsSource = RealTimeMonitor.DefaultFolders(new KavachSettings());
        ExtraFolders.ItemsSource = s.ExtraMonitoredFolders.ToList();
        RefreshEvents();
        _loading = false;
    }

    private void RefreshEvents()
    {
        var events = AppServices.RecentEvents.Take(20).Select(e => new EventRow(e)).ToList();
        EventList.ItemsSource = events;
        NoEvents.Visibility = events.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private static bool GetFeature(KavachSettings s, string key) => key switch
    {
        "DownloadWarnings" => s.DownloadWarnings,
        "AutoQuarantine" => s.AutoQuarantine,
        "RansomwareProtection" => s.RansomwareProtection,
        "ScriptMemoryProtection" => s.ScriptMemoryProtection,
        "UsbAutoScan" => s.UsbAutoScan,
        "SelfProtection" => s.SelfProtection,
        _ => false
    };

    private static void SetFeature(KavachSettings s, string key, bool value)
    {
        switch (key)
        {
            case "DownloadWarnings": s.DownloadWarnings = value; break;
            case "AutoQuarantine": s.AutoQuarantine = value; break;
            case "RansomwareProtection": s.RansomwareProtection = value; break;
            case "ScriptMemoryProtection": s.ScriptMemoryProtection = value; break;
            case "UsbAutoScan": s.UsbAutoScan = value; break;
            case "SelfProtection": s.SelfProtection = value; break;
        }
    }

    private Border BuildFeatureRow(string key, string glyph, string title, string text, bool on, bool enabled)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var bubble = new Border { Style = (Style)FindResource("IconBubble"), Width = 38, Height = 38, CornerRadius = new CornerRadius(10) };
        bubble.SetResourceReference(Border.BackgroundProperty, on ? "SuccessSoftBrush" : "CardHoverBrush");
        var icon = new TextBlock { Text = glyph, Style = (Style)FindResource("Icon"), HorizontalAlignment = HorizontalAlignment.Center };
        icon.SetResourceReference(TextBlock.ForegroundProperty, on ? "SuccessBrush" : "SubTextBrush");
        bubble.Child = icon;
        grid.Children.Add(bubble);

        var texts = new StackPanel { Margin = new Thickness(16, 0, 16, 0), VerticalAlignment = VerticalAlignment.Center };
        texts.Children.Add(new TextBlock { Text = title, Style = (Style)FindResource("CardTitle"), FontSize = 14 });
        texts.Children.Add(new TextBlock { Text = text, Style = (Style)FindResource("Caption"), Margin = new Thickness(0, 3, 0, 0) });
        Grid.SetColumn(texts, 1);
        grid.Children.Add(texts);

        var toggle = new CheckBox { Style = (Style)FindResource("Switch"), IsChecked = on, IsEnabled = enabled };
        toggle.Click += (_, _) =>
        {
            if (_loading) return;
            var value = toggle.IsChecked == true;
            if (!value && !PasswordPrompt.Ask("Turn off " + title))
            {
                toggle.IsChecked = true;
                return;
            }
            AppServices.Context.Settings.Update(s => SetFeature(s, key, value));
            AppServices.Context.Log.Info("Settings", $"{title} turned {(value ? "on" : "off")}");
        };
        Grid.SetColumn(toggle, 2);
        grid.Children.Add(toggle);

        return new Border { Style = (Style)FindResource("Card"), Padding = new Thickness(18, 14, 18, 14), Margin = new Thickness(0, 0, 0, 8), Child = grid };
    }

    private void Master_Click(object sender, RoutedEventArgs e)
    {
        var settings = AppServices.Context.Settings;
        var turningOff = settings.Current.RealTimeProtection;
        if (turningOff)
        {
            if (!PasswordPrompt.Ask("Turn off real-time protection")) return;
            if (!Confirm.Ask("Turn off real-time protection?", "Your PC will not be protected against new threats until you turn it back on.")) return;
        }
        settings.Update(s => s.RealTimeProtection = !turningOff);
        AppServices.Toast(turningOff ? "Real-time protection is off" : "Real-time protection is on", isError: turningOff);
    }

    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose a folder for Kavach to watch" };
        if (dialog.ShowDialog() != true) return;
        AppServices.Context.Settings.Update(s =>
        {
            if (!s.ExtraMonitoredFolders.Contains(dialog.FolderName, StringComparer.OrdinalIgnoreCase)) s.ExtraMonitoredFolders.Add(dialog.FolderName);
        });
        AppServices.Toast("Folder added to real-time protection");
    }

    private void RemoveFolder_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not string folder) return;
        AppServices.Context.Settings.Update(s => s.ExtraMonitoredFolders.RemoveAll(f => string.Equals(f, folder, StringComparison.OrdinalIgnoreCase)));
    }
}
