using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Kavach.App.Services;
using Kavach.Core.Infrastructure;

namespace Kavach.App.Pages;

/// <summary>All user settings.</summary>
public partial class PreferencesPage : UserControl, IKavachPage
{
    private bool _loading;
    private bool _unlocked;

    public PreferencesPage()
    {
        InitializeComponent();
    }

    public void OnNavigatedTo(object? parameter)
    {
        var locked = AppServices.Context.Settings.Current.HasPassword && !_unlocked;
        LockPanel.Visibility = locked ? Visibility.Visible : Visibility.Collapsed;
        MainContent.Visibility = locked ? Visibility.Collapsed : Visibility.Visible;
        if (locked)
        {
            UnlockBox.Clear();
            UnlockBox.Focus();
            return;
        }
        Load();
    }

    private void Unlock_Click(object sender, RoutedEventArgs e)
    {
        if (AppServices.Context.Settings.Current.CheckPassword(UnlockBox.Password))
        {
            _unlocked = true;
            UnlockError.Text = "";
            OnNavigatedTo(null);
        }
        else
        {
            UnlockError.Text = "Wrong password.";
            UnlockBox.Clear();
        }
    }

    private void UnlockBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Unlock_Click(sender, e);
    }

    private void Load()
    {
        _loading = true;
        var s = AppServices.Context.Settings.Current;
        ScanArchives.IsChecked = s.ScanArchives;
        SkipMedia.IsChecked = s.SkipMediaFiles;
        UseCache.IsChecked = s.UseScanCache;
        foreach (ComboBoxItem item in MaxSize.Items)
        {
            if ((string)item.Tag == s.MaxFileSizeMb.ToString()) MaxSize.SelectedItem = item;
        }
        if (MaxSize.SelectedItem == null) MaxSize.SelectedIndex = 2;

        PerfLow.IsChecked = s.Performance == PerformanceMode.Low;
        PerfBalanced.IsChecked = s.Performance == PerformanceMode.Balanced;
        PerfFast.IsChecked = s.Performance == PerformanceMode.Fast;
        PauseBattery.IsChecked = s.PauseOnBattery;
        PauseFullscreen.IsChecked = s.PauseWhenFullscreen;

        ContextMenuToggle.IsChecked = s.ContextMenuEnabled;
        StartWithWindows.IsChecked = s.StartWithWindows;
        MinimizeToTray.IsChecked = s.MinimizeToTray;
        ThemeDark.IsChecked = s.Theme != "Light";
        ThemeLight.IsChecked = s.Theme == "Light";

        VtKey.Password = s.VirusTotalApiKey ?? "";
        AbuseKey.Password = s.AbuseChAuthKey ?? "";

        PasswordState.Text = s.HasPassword ? "A password is set." : "No password. Anyone using this PC can change Kavach's settings.";
        RemovePasswordButton.Visibility = s.HasPassword ? Visibility.Visible : Visibility.Collapsed;

        ServiceText.Text = AppServices.ServiceConnected
            ? "Running. Protection continues even when this window is closed or you sign out."
            : "Not running. Protection runs inside this app while it is open. Install Kavach with the setup program to add the always-on service.";
        _loading = false;
    }

    private void Save_Changed(object sender, SelectionChangedEventArgs e) => Save();
    private void Save_Click(object sender, RoutedEventArgs e) => Save();

    private void Save()
    {
        if (_loading) return;
        var theme = ThemeLight.IsChecked == true ? "Light" : "Dark";
        var context = ContextMenuToggle.IsChecked == true;
        var start = StartWithWindows.IsChecked == true;
        var maxSize = int.TryParse((MaxSize.SelectedItem as ComboBoxItem)?.Tag as string, out var mb) ? mb : 100;

        AppServices.Context.Settings.Update(s =>
        {
            s.ScanArchives = ScanArchives.IsChecked == true;
            s.SkipMediaFiles = SkipMedia.IsChecked == true;
            s.UseScanCache = UseCache.IsChecked == true;
            s.MaxFileSizeMb = maxSize;
            s.Performance = PerfLow.IsChecked == true ? PerformanceMode.Low : PerfFast.IsChecked == true ? PerformanceMode.Fast : PerformanceMode.Balanced;
            s.PauseOnBattery = PauseBattery.IsChecked == true;
            s.PauseWhenFullscreen = PauseFullscreen.IsChecked == true;
            s.ContextMenuEnabled = context;
            s.StartWithWindows = start;
            s.MinimizeToTray = MinimizeToTray.IsChecked == true;
            s.Theme = theme;
        });

        try
        {
            if (context) WindowsIntegration.RegisterContextMenu();
            else WindowsIntegration.UnregisterContextMenu();
            WindowsIntegration.SetStartWithWindows(start);
        }
        catch (Exception ex)
        {
            AppServices.Toast("Could not update Windows settings: " + ex.Message, isError: true);
        }

        App.ApplyTheme(theme);
    }

    private void ClearCache_Click(object sender, RoutedEventArgs e)
    {
        AppServices.Context.Cache.Reset(AppServices.Context.Fingerprint);
        AppServices.Toast("Scan cache cleared — the next scan checks every file again");
    }

    private void SaveKeys_Click(object sender, RoutedEventArgs e)
    {
        var vt = VtKey.Password.Trim();
        var abuse = AbuseKey.Password.Trim();
        AppServices.Context.Settings.Update(s =>
        {
            s.VirusTotalApiKey = vt.Length == 0 ? null : vt;
            s.AbuseChAuthKey = abuse.Length == 0 ? null : abuse;
        });
        AppServices.Toast("Keys saved");
    }

    private void VtLink_Click(object sender, RoutedEventArgs e) => WindowsIntegration.OpenUrl("https://www.virustotal.com/gui/join-us");
    private void AbuseLink_Click(object sender, RoutedEventArgs e) => WindowsIntegration.OpenUrl("https://auth.abuse.ch/");

    private void SetPassword_Click(object sender, RoutedEventArgs e)
    {
        if (NewPassword.Password.Length < 4)
        {
            AppServices.Toast("Use at least 4 characters", isError: true);
            return;
        }
        if (NewPassword.Password != RepeatPassword.Password)
        {
            AppServices.Toast("The two passwords are different", isError: true);
            return;
        }
        var password = NewPassword.Password;
        AppServices.Context.Settings.Update(s => s.SetPassword(password));
        NewPassword.Clear();
        RepeatPassword.Clear();
        _unlocked = true;
        AppServices.Context.Log.Info("Settings", "Settings password set");
        AppServices.Toast("Password set");
        Load();
    }

    private void RemovePassword_Click(object sender, RoutedEventArgs e)
    {
        if (!Confirm.Ask("Remove password?", "Anyone using this PC will be able to change Kavach's settings.")) return;
        AppServices.Context.Settings.Update(s => s.SetPassword(null));
        AppServices.Context.Log.Warning("Settings", "Settings password removed");
        AppServices.Toast("Password removed");
        Load();
    }
}
