using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Kavach.App.Services;

/// <summary>Asks for the settings password before protected changes.</summary>
public static class PasswordPrompt
{
    /// <summary>Returns true if no password is set, or the user typed the right one.</summary>
    public static bool Ask(string action)
    {
        var settings = AppServices.Context.Settings.Current;
        if (!settings.HasPassword) return true;

        var box = new PasswordBox { Style = (Style)Application.Current.FindResource("PasswordInput"), Margin = new Thickness(0, 12, 0, 0) };
        var error = new TextBlock { Style = (Style)Application.Current.FindResource("Caption"), Foreground = Ui.Res("DangerBrush"), Margin = new Thickness(0, 8, 0, 0) };
        var ok = new Button { Content = "Unlock", Style = (Style)Application.Current.FindResource("PrimaryButton"), IsDefault = true, Margin = new Thickness(8, 0, 0, 0) };
        var cancel = new Button { Content = "Cancel", Style = (Style)Application.Current.FindResource("SecondaryButton"), IsCancel = true };

        var window = new Window
        {
            Title = "Kavach — password required",
            Width = 400,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Background = Ui.Res("PanelBgBrush"),
            ShowInTaskbar = false
        };
        var owner = Application.Current.Windows.OfType<Window>().FirstOrDefault(w => w.IsVisible && w.IsActive)
                    ?? Application.Current.MainWindow;
        if (owner != null && owner != window && owner.IsVisible) window.Owner = owner;
        else window.WindowStartupLocation = WindowStartupLocation.CenterScreen;

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 18, 0, 0) };
        buttons.Children.Add(cancel);
        buttons.Children.Add(ok);

        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(new TextBlock { Text = "Password required", Style = (Style)Application.Current.FindResource("CardTitle") });
        panel.Children.Add(new TextBlock
        {
            Text = $"Enter the Kavach settings password to {action.ToLowerInvariant()}.",
            Style = (Style)Application.Current.FindResource("Caption"),
            Margin = new Thickness(0, 6, 0, 0)
        });
        panel.Children.Add(box);
        panel.Children.Add(error);
        panel.Children.Add(buttons);
        window.Content = panel;


        var result = false;
        ok.Click += (_, _) =>
        {
            if (AppServices.Context.Settings.Current.CheckPassword(box.Password))
            {
                result = true;
                window.Close();
            }
            else
            {
                error.Text = "Wrong password. Try again.";
                box.Clear();
                box.Focus();
            }
        };
        window.Loaded += (_, _) => box.Focus();
        window.ShowDialog();
        return result;
    }
}

public static class Confirm
{
    public static bool Ask(string title, string message)
    {
        var owner = Application.Current.MainWindow;
        var result = owner != null && owner.IsVisible
            ? MessageBox.Show(owner, message, title, MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No)
            : MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        return result == MessageBoxResult.Yes;
    }

    public static void Info(string title, string message)
    {
        var owner = Application.Current.MainWindow;
        if (owner != null && owner.IsVisible) MessageBox.Show(owner, message, title, MessageBoxButton.OK, MessageBoxImage.Information);
        else MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
