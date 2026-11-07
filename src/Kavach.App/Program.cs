using System;

namespace Kavach.App;

/// <summary>Entry point of Kavach.exe.</summary>
public static class Program
{
    [STAThread]
    public static void Main()
    {
        var app = new App();
        app.InitializeComponent(); // loads the themes and styles from App.xaml
        app.Run();
    }
}
