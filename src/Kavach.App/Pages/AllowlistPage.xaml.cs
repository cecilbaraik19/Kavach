using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Microsoft.Win32;

namespace Kavach.App.Pages;

/// <summary>Exclusions: folders/files and trusted hashes.</summary>
public partial class AllowlistPage : UserControl, IKavachPage
{
    public AllowlistPage()
    {
        InitializeComponent();
    }

    public void OnNavigatedTo(object? parameter) => Refresh();

    private void Refresh()
    {
        var s = AppServices.Context.Settings.Current;
        PathList.ItemsSource = s.ExcludedPaths.ToList();
        HashList.ItemsSource = s.AllowedHashes.ToList();
        NoPaths.Visibility = s.ExcludedPaths.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        NoHashes.Visibility = s.AllowedHashes.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Add(string path)
    {
        if (!PasswordPrompt.Ask("Change the allowlist")) return;
        AppServices.Context.Settings.Update(s =>
        {
            if (!s.ExcludedPaths.Contains(path, StringComparer.OrdinalIgnoreCase)) s.ExcludedPaths.Add(path);
        });
        AppServices.Context.Log.Warning("Allowlist", "Excluded from scanning: " + path);
        Refresh();
    }

    private void AddFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a file Kavach should skip" };
        if (dialog.ShowDialog() == true) Add(dialog.FileName);
    }

    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose a folder Kavach should skip" };
        if (dialog.ShowDialog() == true) Add(dialog.FolderName);
    }

    private void RemovePath_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not string path) return;
        AppServices.Context.Settings.Update(s => s.ExcludedPaths.RemoveAll(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase)));
        Refresh();
    }

    private void RemoveHash_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not string hash) return;
        AppServices.Context.Settings.Update(s => s.AllowedHashes.RemoveAll(h => string.Equals(h, hash, StringComparison.OrdinalIgnoreCase)));
        Refresh();
    }
}
