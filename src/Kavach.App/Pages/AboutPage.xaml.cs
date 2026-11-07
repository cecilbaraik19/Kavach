using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Kavach.Core.Engine;
using Kavach.Core.Infrastructure;

namespace Kavach.App.Pages;

/// <summary>About Kavach, plus the EICAR self-test.</summary>
public partial class AboutPage : UserControl, IKavachPage
{
    public AboutPage()
    {
        InitializeComponent();
    }

    public void OnNavigatedTo(object? parameter)
    {
        VersionText.Text = $"Kavach Antivirus v{AppPaths.Version}, developed by {AppPaths.Publisher}";
        ShowUpdateState();
        PathsText.Text = $"Program:  {AppPaths.AppDir}\nData:     {AppPaths.DataDir}\nRunning:  {AppServices.ProtectionHostDescription}" +
                         (AppServices.IsAdmin ? "\nRights:   Administrator" : "\nRights:   Standard user");
    }

    private void Eicar_Click(object sender, RoutedEventArgs e)
    {
        // The EICAR text is stored backwards so Kavach's own program file is never flagged by other antivirus products.
        var eicar = Obf.R(@"*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\4[PA@%P!O5X");
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var path = Path.Combine(desktop, "kavach-eicar-test.com");
        try
        {
            File.WriteAllText(path, eicar);
            AppServices.Context.Log.Info("Self-test", "EICAR test file created on the Desktop");
            AppServices.Toast(AppServices.Context.Settings.Current.RealTimeProtection
                ? "EICAR test file created on your Desktop — watch for Kavach's alert"
                : "EICAR test file created. Real-time protection is off, so run a Quick scan to find it.");
        }
        catch (Exception ex)
        {
            AppServices.Toast("Could not create the test file (another antivirus may have blocked it): " + ex.Message, isError: true);
        }
    }

    // ───────── Kavach updates ─────────

    private void ShowUpdateState(string? message = null)
    {
        var s = AppServices.Context.Settings.Current;
        var update = AppServices.AvailableUpdate;
        if (update != null)
        {
            UpdateText.Text = message ?? $"Kavach v{update.Version} is available (you have v{AppPaths.Version})." +
                              (string.IsNullOrWhiteSpace(update.Notes) ? "" : "\n" + Shorten(update.Notes, 300));
            InstallUpdateButton.Visibility = Visibility.Visible;
        }
        else
        {
            UpdateText.Text = message ?? $"You have v{AppPaths.Version}. Kavach checks github.com/{s.UpdateRepository} for a new version once a day" +
                              (s.LastAppUpdateCheck is { } last ? $" (last checked {Ui.TimeAgo(last)})." : ".");
            InstallUpdateButton.Visibility = Visibility.Collapsed;
        }
    }

    private static string Shorten(string text, int max)
    {
        text = text.Replace("\r", "").Trim();
        return text.Length <= max ? text : text[..max] + "…";
    }

    private async void CheckUpdate_Click(object sender, RoutedEventArgs e)
    {
        CheckUpdateButton.IsEnabled = false;
        UpdateText.Text = "Checking GitHub for a new version…";
        try
        {
            var result = await AppServices.AppUpdater.CheckAsync();
            AppServices.AvailableUpdate = result.Update;
            ShowUpdateState(result.Update == null ? result.Message : null);
            if (!result.Success) AppServices.Toast(result.Message, isError: true);
        }
        finally
        {
            CheckUpdateButton.IsEnabled = true;
        }
    }

    private async void InstallUpdate_Click(object sender, RoutedEventArgs e)
    {
        var update = AppServices.AvailableUpdate;
        if (update == null) return;

        InstallUpdateButton.IsEnabled = false;
        CheckUpdateButton.IsEnabled = false;
        UpdateProgress.Visibility = Visibility.Visible;
        UpdateProgress.Value = 0;
        UpdateText.Text = $"Downloading Kavach v{update.Version}…";
        try
        {
            var progress = new Progress<double>(p => UpdateProgress.Value = p);
            var (ok, message, path) = await AppServices.AppUpdater.DownloadAsync(update, progress);
            if (!ok || path == null)
            {
                ShowUpdateState(message);
                AppServices.Toast(message, isError: true);
                return;
            }

            UpdateText.Text = "Verified. Starting the installer — click Yes when Windows asks for permission.";
            var started = AppServices.AppUpdater.StartInstaller(path, out var startMessage);
            UpdateText.Text = startMessage;
            AppServices.Toast(startMessage, isError: !started);
        }
        finally
        {
            UpdateProgress.Visibility = Visibility.Collapsed;
            InstallUpdateButton.IsEnabled = true;
            CheckUpdateButton.IsEnabled = true;
        }
    }

    private void OpenData_Click(object sender, RoutedEventArgs e) => WindowsIntegration.OpenInExplorer(AppPaths.DataDir);
    private void OpenApp_Click(object sender, RoutedEventArgs e) => WindowsIntegration.OpenInExplorer(AppPaths.AppDir);
}
