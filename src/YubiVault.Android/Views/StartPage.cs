using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using YubiVault.Android.Platform;
using YubiVault.Android.Resources;

namespace YubiVault.Android.Views;

/// <summary>First page: open or create a vault, or pick one opened before.</summary>
sealed class StartPage : UserControl
{
    readonly MainView _main;
    readonly StackPanel _recent = new() { Spacing = 4 };
    readonly TextBlock _recentHeader = Ui.Text(Strings.RecentVaults, 16, FontWeight.SemiBold);

    public StartPage(MainView main)
    {
        _main = main;
        var logo = new Image
        {
            Source = new Bitmap(AssetLoader.Open(new Uri("avares://YubiVault.Android/Assets/yubivault.png"))),
            Width = 88,
            Height = 88,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 24, 0, 0),
        };
        var name = new TextBlock { Text = "YubiVault", FontSize = 28, FontWeight = FontWeight.SemiBold, HorizontalAlignment = HorizontalAlignment.Center };
        var tagline = Ui.Hint(Strings.AppTagline);
        tagline.TextAlignment = TextAlignment.Center;

        var content = Ui.Column(
            logo, name, tagline,
            Ui.Button(Strings.OpenVault, OpenVault, accent: true, icon: Ui.LockIcon),
            Ui.Button(Strings.CreateVault, () => _main.Show(new CreatePage(_main)), icon: Ui.PlusIcon),
            _recentHeader,
            _recent);
        _recentHeader.Margin = new Thickness(0, 12, 0, 0);
        Content = new ScrollViewer { Content = content };
        LoadRecent();
    }

    void LoadRecent()
    {
        _recent.Children.Clear();
        var recent = _main.Platform.RecentVaults;
        _recentHeader.IsVisible = recent.Count > 0;
        foreach (var document in recent)
            _recent.Children.Add(RecentRow(document));
    }

    Control RecentRow(VaultDocument document)
    {
        var open = new Button
        {
            Content = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 12,
                Children =
                {
                    new PathIcon { Data = Ui.LockIcon, Width = 20, Height = 20 },
                    new TextBlock { Text = document.DisplayName, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis },
                },
            },
            MinHeight = Ui.TouchSize,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Background = Brushes.Transparent,
        };
        open.Click += (_, _) => _main.Show(new UnlockPage(_main, document));

        var more = Ui.IconButton(Ui.MoreIcon, MobileStrings.More);
        var remove = new MenuItem { Header = MobileStrings.RemoveFromList };
        remove.Click += (_, _) =>
        {
            _main.Platform.RemoveRecent(document);
            LoadRecent();
        };
        more.Flyout = new MenuFlyout { Items = { remove } };

        var row = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        row.Children.Add(open);
        Grid.SetColumn(more, 1);
        row.Children.Add(more);
        return row;
    }

    async void OpenVault()
    {
        try
        {
            var document = await _main.Platform.PickVaultAsync();
            if (document is not null)
                _main.Show(new UnlockPage(_main, document));
        }
        catch (Exception e)
        {
            await _main.ShowErrorAsync(e);
        }
    }
}
