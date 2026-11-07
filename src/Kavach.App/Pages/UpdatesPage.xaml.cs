using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Kavach.Core.Infrastructure;
using Microsoft.Win32;

namespace Kavach.App.Pages;

/// <summary>Download and import signatures.</summary>
public partial class UpdatesPage : UserControl, IKavachPage
{
    public UpdatesPage()
    {
        InitializeComponent();
        AppServices.Context.SignaturesReloaded += () => AppServices.Run(Refresh);
    }

    public void OnNavigatedTo(object? parameter) => Refresh();

    private void Refresh()
    {
        var ctx = AppServices.Context;
        NumHashes.Text = ctx.Hashes.Count.ToString("N0");
        NumRules.Text = ctx.Rules.Rules.Count.ToString("N0");
        NumVersion.Text = ctx.Hashes.VersionInfo.Version.ToString();
        NumUpdated.Text = Ui.TimeAgo(ctx.Hashes.VersionInfo.Updated);
        NumSource.Text = ctx.Hashes.VersionInfo.Source;

        var ruleFiles = ctx.Rules.Rules.Select(r => r.SourceFile).Distinct().ToList();
        FilesText.Text = "Hash lists: " + (ctx.Hashes.LoadedFiles.Count > 0 ? string.Join(", ", ctx.Hashes.LoadedFiles) : "none") +
                         "\nRule files: " + (ruleFiles.Count > 0 ? string.Join(", ", ruleFiles) : "none");
        RuleErrors.Text = ctx.Rules.Errors.Count == 0 ? "" : $"{ctx.Rules.Errors.Count} rule(s) skipped: " + string.Join(" | ", ctx.Rules.Errors.Take(3));
        RuleErrors.Visibility = ctx.Rules.Errors.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    private void ShowResult(SignatureUpdater.UpdateResult result)
    {
        StatusText.Visibility = Visibility.Visible;
        StatusText.Text = result.Message;
        StatusText.SetResourceReference(TextBlock.ForegroundProperty, result.Success ? "SuccessBrush" : "DangerBrush");
        AppServices.Toast(result.Message, !result.Success);
        Refresh();
        AppServices.RaiseStatus();
    }

    private async void Download_Click(object sender, RoutedEventArgs e)
    {
        DownloadButton.IsEnabled = false;
        DownloadText.Text = "Downloading…";
        try
        {
            ShowResult(await AppServices.Updater.DownloadAllAsync());
        }
        finally
        {
            DownloadButton.IsEnabled = true;
            DownloadText.Text = "Download latest";
        }
    }

    private async void ImportHashes_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a hash list", Filter = "Hash lists (*.txt;*.csv)|*.txt;*.csv|All files (*.*)|*.*" };
        if (dialog.ShowDialog() != true) return;
        var path = dialog.FileName;
        ShowResult(await Task.Run(() => AppServices.Updater.ImportHashFile(path)));
    }

    private async void ImportRules_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a YARA rule file", Filter = "YARA rules (*.yar;*.yara)|*.yar;*.yara|All files (*.*)|*.*" };
        if (dialog.ShowDialog() != true) return;
        var path = dialog.FileName;
        ShowResult(await Task.Run(() => AppServices.Updater.ImportRuleFile(path)));
    }

    private void AddHash_Click(object sender, RoutedEventArgs e)
    {
        ShowResult(AppServices.Updater.AddHash(HashInput.Text, HashName.Text));
        HashInput.Clear();
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e) => WindowsIntegration.OpenInExplorer(AppPaths.SignaturesDir);

    private async void Reload_Click(object sender, RoutedEventArgs e)
    {
        await Task.Run(() => AppServices.Context.ReloadSignatures());
        AppServices.Toast("Signatures reloaded");
    }
}
