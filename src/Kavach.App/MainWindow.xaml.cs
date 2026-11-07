using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using Kavach.App.Pages;
using Kavach.App.Services;
using Kavach.Core;
using Kavach.Core.Infrastructure;

namespace Kavach.App;

/// <summary>Pages implement this to refresh when they are shown.</summary>
public interface IKavachPage
{
    void OnNavigatedTo(object? parameter);
}

/// <summary>Main window: header bar, sidebar navigation and the page area.</summary>
public partial class MainWindow : Window
{
    private sealed class NavItem
    {
        public string Key = "";
        public string Title = "";
        public string Glyph = "";
        public List<NavItem> Children = new();
        public Func<int>? Badge;
        public Button? Button;
        public StackPanel? ChildPanel;
        public TextBlock? Chevron;
        public Border? BadgeBorder;
        public TextBlock? BadgeText;
        public NavItem? Parent;
    }

    private readonly List<NavItem> _nav = new();
    private readonly Dictionary<string, UserControl> _pages = new();
    private readonly DispatcherTimer _toastTimer = new() { Interval = TimeSpan.FromSeconds(4) };
    private string _currentKey = "";

    public MainWindow()
    {
        InitializeComponent();
        BuildNavigation();

        AppServices.StatusChanged += UpdateStatus;
        AppServices.ToastRequested += ShowToast;
        _toastTimer.Tick += (_, _) =>
        {
            _toastTimer.Stop();
            Toast.Visibility = Visibility.Collapsed;
        };

        AdminButton.Visibility = AppServices.IsAdmin ? Visibility.Collapsed : Visibility.Visible;
        Title = AppServices.IsAdmin ? "Kavach (Administrator)" : "Kavach";

        SourceInitialized += (_, _) => ApplyTitleBarTheme();
        Closing += OnClosing;

        UpdateStatus();
        Navigate("home");
    }

    // ───────────────────────── Navigation ─────────────────────────

    private void BuildNavigation()
    {
        _nav.Add(new NavItem { Key = "home", Title = "Home", Glyph = "" });
        _nav.Add(new NavItem
        {
            Key = "protection", Title = "Protection", Glyph = "",
            Children =
            {
                new NavItem { Key = "scan", Title = "Malware Scanner", Glyph = "" },
                new NavItem { Key = "realtime", Title = "Real-time Protection", Glyph = "" },
                new NavItem { Key = "system", Title = "System Check", Glyph = "" },
                new NavItem { Key = "network", Title = "Network Monitor", Glyph = "" }
            }
        });
        _nav.Add(new NavItem { Key = "label:MANAGE" });
        _nav.Add(new NavItem
        {
            Key = "quarantine", Title = "Quarantine", Glyph = "",
            Badge = () => AppServices.Context.Quarantine.List().Count
        });
        _nav.Add(new NavItem { Key = "allowlist", Title = "Allowlist", Glyph = "" });
        _nav.Add(new NavItem { Key = "updates", Title = "Signature Updates", Glyph = "" });
        _nav.Add(new NavItem
        {
            Key = "activity-group", Title = "Activity & History", Glyph = "",
            Children =
            {
                new NavItem { Key = "history", Title = "Scan History", Glyph = "" },
                new NavItem { Key = "activity", Title = "Activity Log", Glyph = "" }
            }
        });

        foreach (var item in _nav)
        {
            if (item.Key.StartsWith("label:"))
            {
                NavPanel.Children.Add(new TextBlock
                {
                    Text = item.Key[6..],
                    Style = (Style)FindResource("Eyebrow"),
                    Margin = new Thickness(12, 18, 0, 8)
                });
                continue;
            }
            NavPanel.Children.Add(CreateNavButton(item, isChild: false));
            if (item.Children.Count > 0)
            {
                item.ChildPanel = new StackPanel { Margin = new Thickness(22, 2, 0, 6), Visibility = Visibility.Collapsed };
                foreach (var child in item.Children)
                {
                    child.Parent = item;
                    item.ChildPanel.Children.Add(CreateNavButton(child, isChild: true));
                }
                NavPanel.Children.Add(item.ChildPanel);
            }
        }

        var prefs = new NavItem { Key = "preferences", Title = "Preferences", Glyph = "" };
        var about = new NavItem { Key = "about", Title = "About Kavach", Glyph = "" };
        _nav.Add(prefs);
        _nav.Add(about);
        BottomNav.Children.Add(CreateNavButton(prefs, false));
        BottomNav.Children.Add(CreateNavButton(about, false));
    }

    private Button CreateNavButton(NavItem item, bool isChild)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var icon = new TextBlock
        {
            Text = item.Glyph,
            Style = (Style)FindResource("Icon"),
            FontSize = isChild ? 12.5 : 15,
            Margin = new Thickness(0, 0, isChild ? 10 : 12, 0)
        };
        icon.SetBinding(TextBlock.ForegroundProperty, new System.Windows.Data.Binding("Foreground")
        {
            RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.FindAncestor, typeof(Button), 1)
        });
        grid.Children.Add(icon);

        var title = new TextBlock
        {
            Text = item.Title,
            FontSize = isChild ? 12.5 : 13,
            FontWeight = isChild ? FontWeights.Normal : FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
            TextTrimming = TextTrimming.CharacterEllipsis
        };
        Grid.SetColumn(title, 1);
        grid.Children.Add(title);

        if (item.Badge != null)
        {
            item.BadgeText = new TextBlock { FontSize = 10.5, FontWeight = FontWeights.Bold, Foreground = Ui.Res("OnAccentBrush") };
            item.BadgeBorder = new Border
            {
                Background = Ui.Res("AccentBrush"),
                CornerRadius = new CornerRadius(9),
                MinWidth = 18,
                Height = 18,
                Padding = new Thickness(5, 0, 5, 0),
                Child = item.BadgeText,
                Visibility = Visibility.Collapsed,
                Margin = new Thickness(6, 0, 4, 0)
            };
            item.BadgeText.HorizontalAlignment = HorizontalAlignment.Center;
            item.BadgeText.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(item.BadgeBorder, 2);
            grid.Children.Add(item.BadgeBorder);
        }

        if (item.Children.Count > 0)
        {
            item.Chevron = new TextBlock { Text = "", Style = (Style)FindResource("Icon"), FontSize = 10, Margin = new Thickness(6, 0, 0, 0) };
            Grid.SetColumn(item.Chevron, 3);
            grid.Children.Add(item.Chevron);
        }

        var button = new Button
        {
            Style = (Style)FindResource(isChild ? "NavSubButton" : "NavButton"),
            Content = grid,
            Tag = ""
        };
        button.Click += (_, _) =>
        {
            if (item.Children.Count > 0)
            {
                var open = item.ChildPanel!.Visibility != Visibility.Visible;
                SetExpanded(item, open);
                if (open && !item.Children.Any(c => c.Key == _currentKey)) Navigate(item.Children[0].Key);
            }
            else
            {
                Navigate(item.Key);
            }
        };
        item.Button = button;
        return button;
    }

    private static void SetExpanded(NavItem item, bool open)
    {
        if (item.ChildPanel == null) return;
        item.ChildPanel.Visibility = open ? Visibility.Visible : Visibility.Collapsed;
        if (item.Chevron != null) item.Chevron.Text = open ? "" : "";
    }

    private IEnumerable<NavItem> AllItems() => _nav.Concat(_nav.SelectMany(n => n.Children));

    public void Navigate(string key, object? parameter = null)
    {
        if (!_pages.TryGetValue(key, out var page))
        {
            page = CreatePage(key);
            _pages[key] = page;
        }

        _currentKey = key;
        PageHost.Content = page;

        foreach (var item in AllItems())
        {
            if (item.Button == null) continue;
            var selected = item.Key == key;
            var parentOfSelected = item.Children.Any(c => c.Key == key);
            item.Button.Tag = selected ? "selected" : parentOfSelected ? "active" : "";
            if (parentOfSelected) SetExpanded(item, true);
        }

        (page as IKavachPage)?.OnNavigatedTo(parameter);
        UpdateBadges();
    }

    private static UserControl CreatePage(string key) => key switch
    {
        "scan" => new ScanPage(),
        "realtime" => new RealTimePage(),
        "system" => new SystemCheckPage(),
        "network" => new NetworkPage(),
        "quarantine" => new QuarantinePage(),
        "allowlist" => new AllowlistPage(),
        "updates" => new UpdatesPage(),
        "history" => new HistoryPage(),
        "activity" => new ActivityPage(),
        "schedules" => new SchedulesPage(),
        "preferences" => new PreferencesPage(),
        "about" => new AboutPage(),
        _ => new HomePage()
    };

    private void SchedulesCard_Click(object sender, RoutedEventArgs e) => Navigate("schedules");

    /// <summary>Start a scan and show the scanner page.</summary>
    public void StartScan(ScanType type)
    {
        Navigate("scan", new ScanRequest(type, null));
    }

    /// <summary>Scan files/folders (right-click menu, drag and drop).</summary>
    public void ScanPaths(string[] paths)
    {
        Navigate("scan", new ScanRequest(ScanType.Custom, paths));
    }

    // ───────────────────────── Status, badges, toasts ─────────────────────────

    private void UpdateStatus()
    {
        var status = AppServices.GetStatus();
        var (fg, bg, text) = status.Level switch
        {
            ProtectionLevel.Protected => ("SuccessBrush", "SuccessSoftBrush", "Protected"),
            ProtectionLevel.Attention => ("WarningBrush", "WarningSoftBrush", "Needs attention"),
            _ => ("DangerBrush", "DangerSoftBrush", "At risk")
        };
        StatusPill.SetResourceReference(Border.BackgroundProperty, bg);
        StatusDot.SetResourceReference(Shape_FillProperty, fg);
        StatusText.SetResourceReference(TextBlock.ForegroundProperty, fg);
        StatusText.Text = text;
        StatusPill.ToolTip = status.Title + " — " + status.Message;

        var next = AppServices.Context.Settings.Current.Schedules
            .Where(s => s.Enabled)
            .Select(s => s.NextRun(DateTime.Now))
            .DefaultIfEmpty()
            .Min();
        ScheduleHint.Text = next == default ? "Automate scans on a schedule" : $"Next scan {next:ddd, dd MMM 'at' HH:mm}";

        UpdateBadges();
    }

    private static readonly DependencyProperty Shape_FillProperty = System.Windows.Shapes.Shape.FillProperty;

    private void UpdateBadges()
    {
        foreach (var item in AllItems().Where(i => i.Badge != null))
        {
            int count;
            try { count = item.Badge!(); } catch { count = 0; }
            if (item.BadgeBorder == null || item.BadgeText == null) continue;
            item.BadgeBorder.Visibility = count > 0 ? Visibility.Visible : Visibility.Collapsed;
            item.BadgeText.Text = count > 99 ? "99+" : count.ToString();
        }
    }

    private void ShowToast(string message, bool isError)
    {
        ToastText.Text = message;
        ToastIcon.Text = isError ? "" : "";
        ToastIcon.SetResourceReference(TextBlock.ForegroundProperty, isError ? "DangerBrush" : "SuccessBrush");
        Toast.Visibility = Visibility.Visible;
        _toastTimer.Stop();
        _toastTimer.Start();
    }

    // ───────────────────────── Header buttons ─────────────────────────

    private void AdminButton_Click(object sender, RoutedEventArgs e)
    {
        if (!WindowsIntegration.RestartAsAdmin()) return;
        App.Current.ExitWithoutPrompt();
    }

    private void ThemeButton_Click(object sender, RoutedEventArgs e)
    {
        var next = AppServices.Context.Settings.Current.Theme == "Light" ? "Dark" : "Light";
        AppServices.Context.Settings.Update(s => s.Theme = next);
        App.ApplyTheme(next);
        ThemeIcon.Text = next == "Light" ? "" : "";
    }

    // ───────────────────────── Window chrome ─────────────────────────

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    /// <summary>Makes the Windows title bar dark or light to match the theme.</summary>
    public void ApplyTitleBarTheme()
    {
        try
        {
            var hwnd = new WindowInteropHelper(this).Handle;
            if (hwnd == IntPtr.Zero) return;
            var dark = AppServices.Context.Settings.Current.Theme != "Light" ? 1 : 0;
            if (DwmSetWindowAttribute(hwnd, 20, ref dark, sizeof(int)) != 0)
                DwmSetWindowAttribute(hwnd, 19, ref dark, sizeof(int)); // older Windows 10 builds
            ThemeIcon.Text = dark == 1 ? "" : "";
        }
        catch
        {
        }
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (App.Current.IsExiting) return;
        if (AppServices.Context.Settings.Current.MinimizeToTray)
        {
            // Keep protecting from the tray
            e.Cancel = true;
            Hide();
            return;
        }
        e.Cancel = true;
        App.Current.ExitApp();
    }
}
