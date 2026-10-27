using System.ComponentModel;
using System.Windows;
using Wpf.Ui.Controls;

namespace YubiVault.App;

public partial class RecoveryCodeWindow : FluentWindow
{
    bool _confirmed;
    bool _copied;

    public RecoveryCodeWindow(string code)
    {
        InitializeComponent();
        CodeText.Text = code;
    }

    void OnCopy(object sender, RoutedEventArgs e)
    {
        Clipboard.SetText(CodeText.Text);
        _copied = true;
    }

    void OnSavedChanged(object sender, RoutedEventArgs e) => ContinueButton.IsEnabled = SavedCheck.IsChecked == true;

    void OnContinue(object sender, RoutedEventArgs e)
    {
        _confirmed = true;
        if (_copied)
            Clipboard.Clear(); // don't leave the code on the clipboard
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // The code is shown only once: closing without confirming would lose it.
        if (!_confirmed)
            e.Cancel = true;
        base.OnClosing(e);
    }
}
