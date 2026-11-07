using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Kavach.Core;

namespace Kavach.App;

/// <summary>Threat level → colour (red for High/Critical, amber for Medium, blue for Low, green for None).</summary>
public sealed class LevelToBrushConverter : IValueConverter
{
    public bool Soft { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var level = value is ThreatLevel l ? l : ThreatLevel.None;
        return Ui.LevelBrush(level, Soft);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value == null || (value is string s && s.Length == 0) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Small helpers shared by all pages.</summary>
public static class Ui
{
    public static Brush Res(string key) =>
        Application.Current?.TryFindResource(key) as Brush ?? Brushes.Gray;

    public static Brush LevelBrush(ThreatLevel level, bool soft = false)
    {
        var key = level switch
        {
            ThreatLevel.Critical or ThreatLevel.High => "Danger",
            ThreatLevel.Medium => "Warning",
            ThreatLevel.Low => "Info",
            _ => "Success"
        };
        return Res(key + (soft ? "SoftBrush" : "Brush"));
    }

    public static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? $"{bytes} B" : $"{value:0.#} {units[unit]}";
    }

    public static string TimeAgo(DateTime? time)
    {
        if (time == null) return "Never";
        var span = DateTime.Now - time.Value;
        if (span.TotalSeconds < 60) return "Just now";
        if (span.TotalMinutes < 60) return $"{(int)span.TotalMinutes} min ago";
        if (span.TotalHours < 24) return $"{(int)span.TotalHours} hour{((int)span.TotalHours == 1 ? "" : "s")} ago";
        if (span.TotalDays < 2) return "Yesterday";
        if (span.TotalDays < 30) return $"{(int)span.TotalDays} days ago";
        return time.Value.ToString("dd MMM yyyy");
    }

    public static string Duration(TimeSpan t) =>
        t.TotalHours >= 1 ? $"{(int)t.TotalHours}h {t.Minutes}m" :
        t.TotalMinutes >= 1 ? $"{t.Minutes}m {t.Seconds}s" : $"{t.Seconds}s";

    public static string ScanTypeName(ScanType type) => type switch
    {
        ScanType.Quick => "Quick scan",
        ScanType.Full => "Full scan",
        ScanType.Custom => "Custom scan",
        ScanType.Processes => "Running programs scan",
        ScanType.System => "System check",
        ScanType.RealTime => "Real-time protection",
        ScanType.Usb => "USB drive scan",
        ScanType.Scheduled => "Scheduled scan",
        _ => type.ToString()
    };
}
