using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Kavach.Core.Infrastructure;

namespace Kavach.App.Pages;

/// <summary>Quarantine vault: restore, delete, check on VirusTotal.</summary>
public partial class QuarantinePage : UserControl, IKavachPage
{
    public QuarantinePage()
    {
        InitializeComponent();
        AppServices.Context.Quarantine.Changed += () => AppServices.Run(Refresh);
    }

    public void OnNavigatedTo(object? parameter) => Refresh();

    private void Refresh()
    {
        var items = AppServices.Context.Quarantine.List();
        ItemList.ItemsSource = items.Select(i => new QuarantineRow(i)).ToList();
        NumItems.Text = items.Count.ToString("N0");
        NumSize.Text = Ui.FormatBytes(items.Sum(i => i.Size));
        NumBlocked.Text = AppServices.Context.Settings.Current.ThreatsBlockedTotal.ToString("N0");
        EmptyCard.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        DeleteAllButton.IsEnabled = items.Count > 0;
    }

    private static QuarantineRow? RowOf(object sender) => (sender as FrameworkElement)?.Tag as QuarantineRow;

    private void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is not { } row) return;
        if (!PasswordPrompt.Ask("Restore a quarantined file")) return;

        var answer = MessageBox.Show(Window.GetWindow(this)!,
            $"Restore \"{row.FileName}\" to:\n{row.OriginalPath}\n\nKavach detected it as {row.ThreatName}. Only restore it if you are sure it is safe.\n\n" +
            "Yes = restore and trust it (never flag again)\nNo = restore only\nCancel = keep it in quarantine",
            "Restore file", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel);
        if (answer == MessageBoxResult.Cancel) return;

        var result = AppServices.Context.Quarantine.Restore(row.Item.Id, addToAllowlist: answer == MessageBoxResult.Yes);
        AppServices.Toast(result.Message, !result.Success);
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is not { } row) return;
        if (!Confirm.Ask("Delete permanently?", $"\"{row.FileName}\" ({row.ThreatName}) will be deleted for good. This cannot be undone.")) return;
        var result = AppServices.Context.Quarantine.Delete(row.Item.Id);
        AppServices.Toast(result.Message, !result.Success);
    }

    private void DeleteAll_Click(object sender, RoutedEventArgs e)
    {
        var count = AppServices.Context.Quarantine.List().Count;
        if (count == 0) return;
        if (!Confirm.Ask("Delete everything in quarantine?", $"{count} item(s) will be deleted permanently. This cannot be undone.")) return;
        var deleted = AppServices.Context.Quarantine.DeleteAll();
        AppServices.Toast($"{deleted} item(s) deleted permanently");
    }

    private async void VirusTotal_Click(object sender, RoutedEventArgs e)
    {
        if (RowOf(sender) is not { } row) return;
        AppServices.Toast("Asking VirusTotal…");
        var report = await VirusTotalClient.LookupAsync(row.Item.Sha256, AppServices.Context.Settings.Current.VirusTotalApiKey);
        if (report.Error != null)
        {
            AppServices.Toast(report.Error, isError: true);
            return;
        }
        if (Confirm.Ask("VirusTotal result — " + row.FileName, report.Summary + "\n\nOpen the full report in your browser?"))
            WindowsIntegration.OpenUrl(report.Link);
    }
}
