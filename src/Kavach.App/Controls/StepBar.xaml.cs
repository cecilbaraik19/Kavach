using System.Windows;
using System.Windows.Controls;

namespace Kavach.App.Controls;

/// <summary>The "01 · 02 · 03" guide strip shown under each page title.</summary>
public partial class StepBar : UserControl
{
    public static readonly DependencyProperty Step1Property =
        DependencyProperty.Register(nameof(Step1), typeof(string), typeof(StepBar), new PropertyMetadata(""));
    public static readonly DependencyProperty Step2Property =
        DependencyProperty.Register(nameof(Step2), typeof(string), typeof(StepBar), new PropertyMetadata(""));
    public static readonly DependencyProperty Step3Property =
        DependencyProperty.Register(nameof(Step3), typeof(string), typeof(StepBar), new PropertyMetadata(""));

    public StepBar()
    {
        InitializeComponent();
    }

    public string Step1 { get => (string)GetValue(Step1Property); set => SetValue(Step1Property, value); }
    public string Step2 { get => (string)GetValue(Step2Property); set => SetValue(Step2Property, value); }
    public string Step3 { get => (string)GetValue(Step3Property); set => SetValue(Step3Property, value); }
}
