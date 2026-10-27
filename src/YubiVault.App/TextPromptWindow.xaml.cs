using System.Windows;
using System.Windows.Input;
using Wpf.Ui.Controls;

namespace YubiVault.App;

public partial class TextPromptWindow : FluentWindow
{
    TextPromptWindow(string title, string prompt, string initial)
    {
        InitializeComponent();
        Title = title;
        Bar.Title = title;
        PromptText.Text = prompt;
        Input.Text = initial;
        Loaded += (_, _) =>
        {
            Input.Focus();
            Input.SelectAll();
        };
    }

    /// <returns>The text entered, or null when cancelled.</returns>
    public static string? Ask(Window owner, string title, string prompt, string initial = "")
    {
        var window = new TextPromptWindow(title, prompt, initial) { Owner = owner };
        return window.ShowDialog() == true ? window.Input.Text : null;
    }

    void OnOk(object sender, RoutedEventArgs e) => DialogResult = true;

    void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

    void OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            DialogResult = true;
        else if (e.Key == Key.Escape)
            DialogResult = false;
    }
}
