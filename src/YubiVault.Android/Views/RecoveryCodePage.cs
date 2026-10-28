using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using YubiVault.Android.Resources;

namespace YubiVault.Android.Views;

/// <summary>Shows a new recovery code once; the user must confirm saving it before going on.</summary>
sealed class RecoveryCodePage : UserControl, IBackHandler
{
    public RecoveryCodePage(MainView main, string code, Action onContinue)
    {
        var codeText = new SelectableTextBlock
        {
            Text = code,
            FontFamily = "monospace",
            FontSize = 22,
            TextWrapping = TextWrapping.Wrap,
            TextAlignment = TextAlignment.Center,
            FlowDirection = FlowDirection.LeftToRight,
        };
        var codeBox = new Border
        {
            Child = codeText,
            Padding = new Thickness(16),
            CornerRadius = new CornerRadius(16),
        }.WithBackground("AppSurfaceBrush");

        var continueButton = Ui.Button(Strings.Continue, onContinue, accent: true);
        continueButton.IsEnabled = false;
        var saved = new CheckBox { Content = Strings.RecoverySaved, MinHeight = Ui.TouchSize };
        saved.IsCheckedChanged += (_, _) => continueButton.IsEnabled = saved.IsChecked == true;

        Content = Ui.Page(
            Ui.TopBar(Strings.RecoveryTitle, null, null),
            Ui.Column(
                Ui.Text(Strings.RecoveryText),
                codeBox,
                Ui.Button(Strings.Copy, () =>
                {
                    main.Platform.CopySensitiveText(code);
                    main.ShowToast(MobileStrings.Copied);
                }),
                saved,
                continueButton));
    }

    /// <summary>Back does nothing: the code must be acknowledged, it is never shown again.</summary>
    public bool OnBack() => true;
}
