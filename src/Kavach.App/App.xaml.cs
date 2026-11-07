using System;
using System.Linq;
using System.Windows;
using System.Windows.Threading;
using Kavach.App.Services;
using Kavach.Core;
using Kavach.Core.Infrastructure;

namespace Kavach.App;

/// <summary>
/// Kavach Antivirus — developed by Cecil Baraik.
/// Starts the engine, the tray icon and the main window.
/// Command line: --tray (start hidden in the tray), --scan "path" (scan a file/folder; used by the right-click menu).
/// </summary>
public partial class App : Application
{
    private TrayIcon? _tray;
    private bool _exiting;

    public static new App Current => (App)Application.Current;
    public MainWindow? Main => MainWindow as MainWindow;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var acquired = SingleInstance.TryAcquire();
        if (!acquired && e.Args.Contains("--elevated", StringComparer.OrdinalIgnoreCase))
        {
            // The non-admin copy is closing; wait for it to let go
            for (var i = 0; i < 25 && !acquired; i++)
            {
                System.Threading.Thread.Sleep(200);
                acquired = SingleInstance.TryAcquire();
            }
        }
        if (!acquired)
        {
            SingleInstance.SendToFirstInstance(e.Args.Length == 0 ? new[] { "--show" } : e.Args);
            Shutdown();
            return;
        }

        DispatcherUnhandledException += OnUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            try { AppServices.Context?.Log.Error("App", "Crash: " + args.ExceptionObject); } catch { }
        };

        try
        {
            AppServices.Initialize(Dispatcher);
        }
        catch (Exception ex)
        {
            MessageBox.Show("Kavach could not start:\n\n" + ex.Message, "Kavach Antivirus", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown();
            return;
        }

        ApplyTheme(AppServices.Context.Settings.Current.Theme);

        // Keep Windows integration in line with the settings
        try
        {
            var s = AppServices.Context.Settings.Current;
            WindowsIntegration.SetStartWithWindows(s.StartWithWindows);
            if (s.ContextMenuEnabled) WindowsIntegration.RegisterContextMenu();
        }
        catch
        {
        }

        var main = new MainWindow();
        MainWindow = main;

        _tray = new TrayIcon(ShowMain, () =>
        {
            ShowMain();
            main.StartScan(ScanType.Quick);
        }, ExitApp);

        SingleInstance.Listen(args => Dispatcher.BeginInvoke(() => HandleArgs(args, fromOtherInstance: true)));

        var startHidden = e.Args.Contains("--tray", StringComparer.OrdinalIgnoreCase);
        if (!startHidden) main.Show();
        HandleArgs(e.Args, fromOtherInstance: false);
    }

    private void HandleArgs(string[] args, bool fromOtherInstance)
    {
        var scanIndex = Array.FindIndex(args, a => a.Equals("--scan", StringComparison.OrdinalIgnoreCase));
        if (scanIndex >= 0 && scanIndex + 1 < args.Length)
        {
            ShowMain();
            Main?.ScanPaths(new[] { args[scanIndex + 1] });
            return;
        }

        if (fromOtherInstance && !args.Contains("--tray", StringComparer.OrdinalIgnoreCase)) ShowMain();
    }

    public void ShowMain()
    {
        var main = Main;
        if (main == null) return;
        if (!main.IsVisible) main.Show();
        if (main.WindowState == WindowState.Minimized) main.WindowState = WindowState.Normal;
        main.Activate();
        main.Topmost = true;  // bring to front
        main.Topmost = false;
        main.Focus();
    }

    public bool IsExiting => _exiting;

    public void ExitApp()
    {
        if (AppServices.Context.Settings.Current.HasPassword && !PasswordPrompt.Ask("Exit Kavach")) return;
        _exiting = true;
        _tray?.Dispose();
        AppServices.Shutdown();
        SingleInstance.Release();
        Shutdown();
    }

    /// <summary>Close without asking for the password (used when restarting as administrator).</summary>
    public void ExitWithoutPrompt()
    {
        _exiting = true;
        _tray?.Dispose();
        AppServices.Shutdown();
        SingleInstance.Release();
        Shutdown();
    }

    /// <summary>Switch between Themes/Dark.xaml and Themes/Light.xaml.</summary>
    public static void ApplyTheme(string theme)
    {
        var dictionaries = Current.Resources.MergedDictionaries;
        var source = new Uri(theme == "Light" ? "Themes/Light.xaml" : "Themes/Dark.xaml", UriKind.Relative);
        dictionaries[0] = new ResourceDictionary { Source = source };
        (Current.MainWindow as MainWindow)?.ApplyTitleBarTheme();
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try { AppServices.Context?.Log.Error("App", e.Exception.ToString()); } catch { }
        AppServices.Toast("Something went wrong: " + e.Exception.Message, isError: true);
        e.Handled = true; // keep the antivirus running
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        base.OnExit(e);
    }
}
