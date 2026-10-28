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
    readonly StackPanel _recent = new() { Spacing = 10 };
    readonly TextBlock _recentHeader = Ui.Text(Strings.RecentVaults, 16, FontWeight.SemiBold);

    public StartPage(MainView main)
    {
        _main = main;
        var logo = new Image
        {
            Source = new Bitmap(AssetLoader.Open(new Uri("avares://YubiVault.Android/Assets/app-icon.png"))),
            Width = 96,
            Height = 96,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 40, 0, 4),
        };
        var name = new TextBlock { Text = "YubiVault", FontSize = 32, FontWeight = FontWeight.Bold, HorizontalAlignment = HorizontalAlignment.Center };
        var tagline = Ui.Hint(Strings.AppTagline);
        tagline.TextAlignment = TextAlignment.Center;
        tagline.Margin = new Thickness(12, 0, 12, 16);

        _recentHeader.Margin = new Thickness(4, 20, 0, 0);
        var content = Ui.Column(
            logo, name, tagline,
            Ui.Button(Strings.OpenVault, OpenVault, accent: true, icon: Ui.LockIcon),
            Ui.Button(Strings.CreateVault, () => _main.Show(new CreatePage(_main)), icon: Ui.PlusIcon),
            _recentHeader,
            _recent);
        content.MaxWidth = 560;
        var theme = ThemeButton();
        theme.HorizontalAlignment = HorizontalAlignment.Right;
        theme.VerticalAlignment = VerticalAlignment.Top;
        theme.Margin = new Thickness(8);
        Content = new Panel { Children = { new ScrollViewer { Content = content }, theme } };
        LoadRecent();
    }

    /// <summary>Top-right button with the dark / light / same-as-phone choice.</summary>
    static Button ThemeButton()
    {
        var button = Ui.IconButton(Ui.ThemeIcon, MobileStrings.Theme);
        var menu = new MenuFlyout();
        foreach (var (value, label) in new[]
        {
            (ThemeSetting.Dark, MobileStrings.ThemeDark),
            (ThemeSetting.Light, MobileStrings.ThemeLight),
            (ThemeSetting.System, MobileStrings.ThemeSystem),
        })
        {
            var item = new MenuItem { Header = label, ToggleType = MenuItemToggleType.Radio, GroupName = "theme" };
            item.Click += (_, _) => ThemeSetting.Set(value);
            menu.Items.Add(item);
        }
        menu.Opening += (_, _) =>
        {
            string current = ThemeSetting.Current;
            int index = current == ThemeSetting.Light ? 1 : current == ThemeSetting.System ? 2 : 0;
            for (int i = 0; i < menu.Items.Count; i++)
                ((MenuItem)menu.Items[i]!).IsChecked = i == index;
        };
        button.Flyout = menu;
        return button;
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
        var texts = new StackPanel
        {
            VerticalAlignment = VerticalAlignment.Center,
            Children =
            {
                new TextBlock
                {
                    Text = Path.GetFileNameWithoutExtension(document.DisplayName),
                    FontSize = 16,
                    FontWeight = FontWeight.SemiBold,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                },
            },
        };
        string location = Location(document);
        if (location.Length > 0)
            texts.Children.Add(new TextBlock { Text = location, FontSize = 13, Opacity = 0.65, TextTrimming = TextTrimming.CharacterEllipsis });
        var badge = Ui.IconBadge(Ui.LockIcon, 44);
        badge.VerticalAlignment = VerticalAlignment.Center;
        var inner = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 14, Children = { badge, texts } };
        Grid.SetColumn(texts, 1);
        var open = new Button
        {
            Content = inner,
            MinHeight = 64,
            Padding = new Thickness(12, 8),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            Classes = { "flat" },
        };
        open.Click += (_, _) => _main.Show(new UnlockPage(_main, document));

        var more = Ui.IconButton(Ui.MoreIcon, MobileStrings.More);
        more.VerticalAlignment = VerticalAlignment.Center;
        var remove = new MenuItem { Header = MobileStrings.RemoveFromList };
        remove.Click += (_, _) =>
        {
            _main.Platform.RemoveRecent(document);
            LoadRecent();
        };
        more.Flyout = new MenuFlyout { Items = { remove } };

        var row = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), Margin = new Thickness(0, 0, 4, 0) };
        row.Children.Add(open);
        Grid.SetColumn(more, 1);
        row.Children.Add(more);
        return Ui.Card(row, 0);
    }

    /// <summary>Where the vault lives, when the document's address tells (local folders): "Download", "Documents/Work"; otherwise empty.</summary>
    static string Location(VaultDocument document)
    {
        try
        {
            string uri = Uri.UnescapeDataString(document.Uri);
            int colon = uri.LastIndexOf(':');
            int slash = uri.LastIndexOf('/');
            if (colon > uri.IndexOf("/document/", StringComparison.Ordinal) && colon < slash)
                return uri[(colon + 1)..slash];
        }
        catch (UriFormatException)
        {
        }
        return "";
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
