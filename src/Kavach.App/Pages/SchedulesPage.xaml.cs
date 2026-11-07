using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Kavach.App.Services;
using Kavach.Core;
using Kavach.Core.Infrastructure;

namespace Kavach.App.Pages;

/// <summary>Create, edit, pause and run scheduled scans.</summary>
public partial class SchedulesPage : UserControl, IKavachPage
{
    private string? _editingId;

    public SchedulesPage()
    {
        InitializeComponent();
        foreach (var day in new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday, DayOfWeek.Saturday, DayOfWeek.Sunday })
            DayBox.Items.Add(new ComboBoxItem { Content = day.ToString(), Tag = day });
        DayBox.SelectedIndex = 0;
        for (var h = 0; h < 24; h++)
        {
            TimeBox.Items.Add(new ComboBoxItem { Content = $"{h:00}:00", Tag = $"{h:00}:00" });
            TimeBox.Items.Add(new ComboBoxItem { Content = $"{h:00}:30", Tag = $"{h:00}:30" });
        }
        TimeBox.SelectedIndex = 18; // 09:00
        AppServices.Context.Settings.Changed += _ => AppServices.Run(() => { if (IsVisible) Refresh(); });
    }

    public void OnNavigatedTo(object? parameter) => Refresh();

    private void Refresh()
    {
        var schedules = AppServices.Context.Settings.Current.Schedules.ToList();
        ScheduleList.ItemsSource = schedules.Select(s => new ScheduleRow(s)).ToList();
        EmptyText.Visibility = schedules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var next = schedules.Where(s => s.Enabled).OrderBy(s => s.NextRun(DateTime.Now)).FirstOrDefault();
        NextCard.Visibility = next == null ? Visibility.Collapsed : Visibility.Visible;
        if (next != null)
        {
            var when = next.NextRun(DateTime.Now);
            NextMonth.Text = when.ToString("MMM").ToUpperInvariant();
            NextDay.Text = when.Day.ToString();
            NextName.Text = next.Name;
            NextWhen.Text = when <= DateTime.Now ? "Due now — starts within a minute" : when.ToString("dddd • HH:mm");
        }
    }

    private void Frequency_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (DayPanel != null && sender is ComboBox box) DayPanel.Visibility = box.SelectedIndex == 1 ? Visibility.Visible : Visibility.Hidden;
    }

    private void New_Click(object sender, RoutedEventArgs e)
    {
        _editingId = null;
        EditorTitle.Text = "New schedule";
        NameBox.Text = "Weekly safety check";
        TypeBox.SelectedIndex = 0;
        FrequencyBox.SelectedIndex = 1;
        DayBox.SelectedIndex = 0;
        TimeBox.SelectedIndex = 18;
        BatteryBox.IsChecked = true;
        Editor.Visibility = Visibility.Visible;
        NameBox.Focus();
    }

    private static ScheduleEntry? EntryOf(object sender) => ((sender as FrameworkElement)?.Tag as ScheduleRow)?.Entry;

    private void Edit_Click(object sender, RoutedEventArgs e)
    {
        if (EntryOf(sender) is not { } entry) return;
        _editingId = entry.Id;
        EditorTitle.Text = "Edit schedule";
        NameBox.Text = entry.Name;
        TypeBox.SelectedIndex = entry.ScanType == ScanType.Full ? 1 : 0;
        FrequencyBox.SelectedIndex = entry.Frequency == ScheduleFrequency.Daily ? 0 : 1;
        DayBox.SelectedItem = DayBox.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (DayOfWeek)i.Tag == entry.Day);
        TimeBox.SelectedItem = TimeBox.Items.OfType<ComboBoxItem>().FirstOrDefault(i => (string)i.Tag == entry.Time) ?? TimeBox.Items[18];
        BatteryBox.IsChecked = entry.SkipOnBattery;
        Editor.Visibility = Visibility.Visible;
    }

    private void CancelEdit_Click(object sender, RoutedEventArgs e) => Editor.Visibility = Visibility.Collapsed;

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var name = string.IsNullOrWhiteSpace(NameBox.Text) ? "Scheduled scan" : NameBox.Text.Trim();
        var type = TypeBox.SelectedIndex == 1 ? ScanType.Full : ScanType.Quick;
        var frequency = FrequencyBox.SelectedIndex == 0 ? ScheduleFrequency.Daily : ScheduleFrequency.Weekly;
        var day = (DayBox.SelectedItem as ComboBoxItem)?.Tag is DayOfWeek d ? d : DayOfWeek.Monday;
        var time = (TimeBox.SelectedItem as ComboBoxItem)?.Tag as string ?? "09:00";
        var battery = BatteryBox.IsChecked == true;

        AppServices.Context.Settings.Update(s =>
        {
            var entry = _editingId == null ? null : s.Schedules.FirstOrDefault(x => x.Id == _editingId);
            if (entry == null)
            {
                entry = new ScheduleEntry();
                s.Schedules.Add(entry);
            }
            entry.Name = name;
            entry.ScanType = type;
            entry.Frequency = frequency;
            entry.Day = day;
            entry.Time = time;
            entry.SkipOnBattery = battery;
            entry.Enabled = true;
            entry.CreatedAt = DateTime.Now; // next run is calculated from now
            entry.LastRun = null;
        });
        AppServices.Context.Log.Info("Schedule", $"Schedule saved: {name} ({(frequency == ScheduleFrequency.Daily ? "daily" : day.ToString())} at {time})");
        Editor.Visibility = Visibility.Collapsed;
        Refresh();
        AppServices.Toast("Schedule saved");
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (EntryOf(sender) is not { } entry) return;
        if (!Confirm.Ask("Delete schedule?", $"Delete \"{entry.Name}\"?")) return;
        AppServices.Context.Settings.Update(s => s.Schedules.RemoveAll(x => x.Id == entry.Id));
        Refresh();
    }

    private void Toggle_Click(object sender, RoutedEventArgs e)
    {
        if (EntryOf(sender) is not { } entry) return;
        var enabled = (sender as CheckBox)?.IsChecked == true;
        AppServices.Context.Settings.Update(s =>
        {
            var x = s.Schedules.FirstOrDefault(i => i.Id == entry.Id);
            if (x != null) x.Enabled = enabled;
        });
        Refresh();
    }

    private void RunNow_Click(object sender, RoutedEventArgs e)
    {
        if (EntryOf(sender) is not { } entry) return;
        (Window.GetWindow(this) as MainWindow)?.StartScan(entry.ScanType == ScanType.Full ? ScanType.Full : ScanType.Quick);
    }
}
