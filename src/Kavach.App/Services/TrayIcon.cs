using System;
using Kavach.Core;
using Forms = System.Windows.Forms;
using Drawing = System.Drawing;

namespace Kavach.App.Services;

/// <summary>Kavach icon near the clock: quick actions and Windows notifications.</summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly Forms.ToolStripMenuItem _realTimeItem;
    private readonly Action _open;
    private readonly Action _quickScan;
    private readonly Action _exit;

    public TrayIcon(Action open, Action quickScan, Action exit)
    {
        _open = open;
        _quickScan = quickScan;
        _exit = exit;

        Drawing.Icon icon;
        try
        {
            icon = Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!) ?? Drawing.SystemIcons.Shield;
        }
        catch
        {
            icon = Drawing.SystemIcons.Shield;
        }

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open Kavach", null, (_, _) => _open());
        menu.Items.Add("Quick scan", null, (_, _) => _quickScan());
        _realTimeItem = new Forms.ToolStripMenuItem("Real-time protection") { CheckOnClick = false };
        _realTimeItem.Click += (_, _) => ToggleRealTime();
        menu.Items.Add(_realTimeItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit Kavach", null, (_, _) => _exit());
        menu.Opening += (_, _) => _realTimeItem.Checked = AppServices.Context.Settings.Current.RealTimeProtection;

        _icon = new Forms.NotifyIcon
        {
            Icon = icon,
            Text = "Kavach Antivirus",
            Visible = true,
            ContextMenuStrip = menu
        };
        _icon.DoubleClick += (_, _) => _open();
        _icon.BalloonTipClicked += (_, _) => _open();

        AppServices.HostEventReceived += Notify;
        AppServices.StatusChanged += UpdateTooltip;
        UpdateTooltip();
    }

    private void ToggleRealTime()
    {
        var settings = AppServices.Context.Settings;
        if (settings.Current.RealTimeProtection)
        {
            if (settings.Current.HasPassword)
            {
                AppServices.Run(() =>
                {
                    if (PasswordPrompt.Ask("Turn off real-time protection")) settings.Update(s => s.RealTimeProtection = false);
                });
                return;
            }
            settings.Update(s => s.RealTimeProtection = false);
        }
        else
        {
            settings.Update(s => s.RealTimeProtection = true);
        }
    }

    private void UpdateTooltip()
    {
        try
        {
            var status = AppServices.GetStatus();
            var text = "Kavach Antivirus — " + status.Title;
            _icon.Text = text.Length > 63 ? text[..63] : text;
        }
        catch
        {
        }
    }

    public void Notify(HostEvent e)
    {
        var icon = e.Level switch
        {
            ThreatLevel.Critical or ThreatLevel.High => Forms.ToolTipIcon.Error,
            ThreatLevel.Medium or ThreatLevel.Low => Forms.ToolTipIcon.Warning,
            _ => Forms.ToolTipIcon.Info
        };
        Show(e.Title, e.Message, icon);
    }

    public void Show(string title, string message, Forms.ToolTipIcon icon = Forms.ToolTipIcon.Info)
    {
        try
        {
            _icon.ShowBalloonTip(6000, title, string.IsNullOrWhiteSpace(message) ? " " : message, icon);
        }
        catch
        {
        }
    }

    public void Dispose()
    {
        AppServices.HostEventReceived -= Notify;
        AppServices.StatusChanged -= UpdateTooltip;
        _icon.Visible = false;
        _icon.Dispose();
    }
}
