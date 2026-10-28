using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace YubiVault.Android.Views;

/// <summary>Small building blocks shared by the pages, which are built in code.</summary>
static class Ui
{
    public const double TouchSize = 48;
    public static readonly IBrush ErrorBrush = new SolidColorBrush(Color.FromRgb(0xD1, 0x34, 0x38));

    public static readonly Geometry FolderIcon = Geometry.Parse("M10,4H4C2.89,4 2,4.89 2,6V18A2,2 0 0,0 4,20H20A2,2 0 0,0 22,18V8C22,6.89 21.1,6 20,6H12L10,4Z");
    public static readonly Geometry FileIcon = Geometry.Parse("M13,9V3.5L18.5,9M6,2C4.89,2 4,2.89 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2H6Z");
    public static readonly Geometry LockIcon = Geometry.Parse("M12,17A2,2 0 0,0 14,15C14,13.89 13.1,13 12,13A2,2 0 0,0 10,15A2,2 0 0,0 12,17M18,8A2,2 0 0,1 20,10V20A2,2 0 0,1 18,22H6A2,2 0 0,1 4,20V10C4,8.89 4.9,8 6,8H7V6A5,5 0 0,1 12,1A5,5 0 0,1 17,6V8H18M12,3A3,3 0 0,0 9,6V8H15V6A3,3 0 0,0 12,3Z");
    public static readonly Geometry KeyIcon = Geometry.Parse("M7,14A2,2 0 0,1 5,12A2,2 0 0,1 7,10A2,2 0 0,1 9,12A2,2 0 0,1 7,14M12.65,10C11.83,7.67 9.61,6 7,6A6,6 0 0,0 1,12A6,6 0 0,0 7,18C9.61,18 11.83,16.33 12.65,14H17V18H21V14H23V10H12.65Z");
    public static readonly Geometry BackIcon = Geometry.Parse("M20,11V13H8L13.5,18.5L12.08,19.92L4.16,12L12.08,4.08L13.5,5.5L8,11H20Z");
    public static readonly Geometry MoreIcon = Geometry.Parse("M12,16A2,2 0 0,1 14,18A2,2 0 0,1 12,20A2,2 0 0,1 10,18A2,2 0 0,1 12,16M12,10A2,2 0 0,1 14,12A2,2 0 0,1 12,14A2,2 0 0,1 10,12A2,2 0 0,1 12,10M12,4A2,2 0 0,1 14,6A2,2 0 0,1 12,8A2,2 0 0,1 10,6A2,2 0 0,1 12,4Z");
    public static readonly Geometry ThemeIcon = Geometry.Parse("M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20V4Z");
    public static readonly Geometry LanguageIcon = Geometry.Parse("M12.87,15.07L10.33,12.56L10.36,12.53C12.1,10.59 13.34,8.36 14.07,6H17V4H10V2H8V4H1V6H12.17C11.5,7.92 10.44,9.75 9,11.35C8.07,10.32 7.3,9.19 6.69,8H4.69C5.42,9.63 6.42,11.17 7.67,12.56L2.58,17.58L4,19L9,14L12.11,17.11L12.87,15.07M18.5,10H16.5L12,22H14L15.12,19H19.87L21,22H23L18.5,10M15.88,17L17.5,12.67L19.12,17H15.88Z");
    public static readonly Geometry PlusIcon = Geometry.Parse("M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z");
    public static readonly Geometry ShieldLockIcon = Geometry.Parse("M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.1 14.8,9.5V11C15.4,11 16,11.6 16,12.3V15.8C16,16.4 15.4,17 14.7,17H9.2C8.6,17 8,16.4 8,15.7V12.2C8,11.6 8.6,11 9.2,11V9.5C9.2,8.1 10.6,7 12,7M12,8.2C11.2,8.2 10.5,8.7 10.5,9.5V11H13.5V9.5C13.5,8.7 12.8,8.2 12,8.2Z");
    public static readonly Geometry NfcIcon = Geometry.Parse("M18,6H13A2,2 0 0,0 11,8V10.28C10.41,10.62 10,11.26 10,12A2,2 0 0,0 12,14C13.11,14 14,13.1 14,12C14,11.26 13.6,10.62 13,10.28V8H16V16H8V8H10V6H6V18H18M20,20H4V4H20M20,2H4A2,2 0 0,0 2,4V20A2,2 0 0,0 4,22H20C21.11,22 22,21.1 22,20V4C22,2.89 21.11,2 20,2Z");
    public static readonly Geometry UsbIcon = Geometry.Parse("M15,7V11H16V13H13V5H15L12,1L9,5H11V13H8V10.93C8.7,10.56 9.2,9.85 9.2,9C9.2,7.78 8.21,6.8 7,6.8C5.78,6.8 4.8,7.78 4.8,9C4.8,9.85 5.3,10.56 6,10.93V13A2,2 0 0,0 8,15H11V18.05C10.29,18.41 9.8,19.15 9.8,20A2.2,2.2 0 0,0 12,22.2A2.2,2.2 0 0,0 14.2,20C14.2,19.15 13.71,18.41 13,18.05V15H16A2,2 0 0,0 18,13V11H19V7H15Z");
    public static readonly Geometry TouchIcon = Geometry.Parse("M10,9A1,1 0 0,1 11,8A1,1 0 0,1 12,9V13.47L13.21,13.6L18.15,15.79C18.68,16.03 19,16.56 19,17.14V21.5C18.97,22.32 18.32,22.97 17.5,23H11C10.62,23 10.26,22.85 10,22.57L5.1,18.37L5.84,17.6C6.03,17.39 6.3,17.28 6.58,17.28H6.8L10,19V9M11,5A4,4 0 0,1 15,9C15,10.5 14.2,11.77 13,12.46V11.24C13.61,10.69 14,9.89 14,9A3,3 0 0,0 11,6A3,3 0 0,0 8,9C8,9.89 8.39,10.69 9,11.24V12.46C7.8,11.77 7,10.5 7,9A4,4 0 0,1 11,5Z");
    public static readonly Geometry ImageIcon = Geometry.Parse("M8.5,13.5L11,16.5L14.5,12L19,18H5M21,19V5C21,3.89 20.1,3 19,3H5A2,2 0 0,0 3,5V19A2,2 0 0,0 5,21H19A2,2 0 0,0 21,19Z");
    public static readonly Geometry VideoIcon = Geometry.Parse("M17,10.5V7A1,1 0 0,0 16,6H4A1,1 0 0,0 3,7V17A1,1 0 0,0 4,18H16A1,1 0 0,0 17,17V13.5L21,17.5V6.5L17,10.5Z");
    public static readonly Geometry AudioIcon = Geometry.Parse("M12,3V13.55C11.41,13.21 10.73,13 10,13C7.79,13 6,14.79 6,17C6,19.21 7.79,21 10,21C12.21,21 14,19.21 14,17V7H18V3H12Z");
    public static readonly Geometry DocumentIcon = Geometry.Parse("M13,9H18.5L13,3.5V9M6,2H14L20,8V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V4C4,2.89 4.89,2 6,2M15,18V16H6V18H15M18,14V12H6V14H18Z");
    public static readonly Geometry ArchiveIcon = Geometry.Parse("M3,3H21V7H3V3M4,8H20V21H4V8M9.5,11A0.5,0.5 0 0,0 9,11.5V13H15V11.5A0.5,0.5 0 0,0 14.5,11H9.5Z");

    public static string Format(string format, params object?[] args) => string.Format(CultureInfo.CurrentCulture, format, args);

    public static bool IsRightToLeft => CultureInfo.CurrentUICulture.TextInfo.IsRightToLeft;

    public static string Size(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.##} GB",
    };

    public static TextBlock Text(string text, double size = 15, FontWeight weight = FontWeight.Normal, double opacity = 1) => new()
    {
        Text = text,
        FontSize = size,
        FontWeight = weight,
        Opacity = opacity,
        TextWrapping = TextWrapping.Wrap,
    };

    public static TextBlock Title(string text) => Text(text, 22, FontWeight.SemiBold);

    public static TextBlock Hint(string text) => Text(text, 14, opacity: 0.75);

    public static TextBlock Error() => new()
    {
        FontSize = 14,
        Foreground = ErrorBrush,
        TextWrapping = TextWrapping.Wrap,
        IsVisible = false,
    };

    public static void ShowError(TextBlock error, string? message)
    {
        error.Text = message;
        error.IsVisible = !string.IsNullOrEmpty(message);
    }

    /// <summary>A full-width pill button: filled for the main action of a page, tonal otherwise.</summary>
    public static Button Button(string text, Action onClick, bool accent = false, Geometry? icon = null)
    {
        var button = new Button
        {
            Content = ButtonContent(text, icon),
            MinHeight = 52,
            FontSize = 16,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            VerticalContentAlignment = VerticalAlignment.Center,
        };
        button.Classes.Add(accent ? "accent" : "tonal");
        button.Click += (_, _) => onClick();
        return button;
    }

    /// <summary>A button that is only its (wrapping) text, in the accent color, for secondary choices.</summary>
    public static Button TextButton(string text, Action onClick)
    {
        var button = new Button
        {
            Content = ButtonText(text),
            MinHeight = TouchSize,
            FontSize = 15,
            HorizontalAlignment = HorizontalAlignment.Center,
            HorizontalContentAlignment = HorizontalAlignment.Center,
        };
        button.Classes.Add("text");
        button.Click += (_, _) => onClick();
        return button;
    }

    static object ButtonContent(string text, Geometry? icon) => icon is null
        ? ButtonText(text)
        : new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 10,
            HorizontalAlignment = HorizontalAlignment.Center,
            Children = { new PathIcon { Data = icon, Width = 20, Height = 20 }, ButtonText(text) },
        };

    /// <summary>Button text that wraps instead of being cut off, for long translations on narrow phones.</summary>
    public static TextBlock ButtonText(string text) => new()
    {
        Text = text,
        TextWrapping = TextWrapping.Wrap,
        TextAlignment = TextAlignment.Center,
        VerticalAlignment = VerticalAlignment.Center,
    };

    /// <summary>A borderless square button with an icon, for top bars and list rows.</summary>
    public static Button IconButton(Geometry icon, string label, Action? onClick = null)
    {
        var button = new Button
        {
            Content = new PathIcon { Data = icon, Width = 22, Height = 22 },
            Width = TouchSize,
            Height = TouchSize,
            Padding = new Thickness(0),
            HorizontalContentAlignment = HorizontalAlignment.Center,
            VerticalContentAlignment = VerticalAlignment.Center,
            Classes = { "flat", "icon" },
        };
        ToolTip.SetTip(button, label);
        Avalonia.Automation.AutomationProperties.SetName(button, label);
        if (onClick is not null)
            button.Click += (_, _) => onClick();
        return button;
    }

    /// <summary>The bar at the top of a page: optional back button, a title with an optional subtitle, and actions.</summary>
    public static Control TopBar(string title, string? subtitle, Action? back, params Control[] actions)
    {
        var grid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"),
            MinHeight = 64,
            Margin = new Thickness(4, 8, 4, 4),
        };
        if (back is not null)
        {
            var backButton = IconButton(BackIcon, Resources.Strings.Back, back);
            // The arrow points to where "back" is, which is the right side in right-to-left languages.
            if (IsRightToLeft)
                backButton.RenderTransform = new ScaleTransform(-1, 1);
            grid.Children.Add(backButton);
        }
        var titles = new StackPanel
        {
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(back is null ? 16 : 4, 0, 4, 0),
            Children = { new TextBlock { Text = title, FontSize = 22, FontWeight = FontWeight.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis } },
        };
        if (!string.IsNullOrEmpty(subtitle))
            titles.Children.Add(new TextBlock { Text = subtitle, FontSize = 13, Opacity = 0.7, TextTrimming = TextTrimming.CharacterEllipsis });
        Grid.SetColumn(titles, 1);
        grid.Children.Add(titles);
        var actionPanel = new StackPanel { Orientation = Orientation.Horizontal };
        foreach (var action in actions)
            actionPanel.Children.Add(action);
        Grid.SetColumn(actionPanel, 2);
        grid.Children.Add(actionPanel);
        return grid;
    }

    /// <summary>A page layout: top bar, scrolling content, and an optional footer pinned to the bottom.</summary>
    public static Control Page(Control topBar, Control content, Control? footer = null)
    {
        var dock = new DockPanel();
        DockPanel.SetDock(topBar, Dock.Top);
        dock.Children.Add(topBar);
        if (footer is not null)
        {
            DockPanel.SetDock(footer, Dock.Bottom);
            dock.Children.Add(footer);
        }
        dock.Children.Add(new ScrollViewer
        {
            Content = content,
            HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled,
        });
        return dock;
    }

    /// <summary>A vertical stack with the page's side margins.</summary>
    public static StackPanel Column(params Control[] children)
    {
        var panel = new StackPanel { Spacing = 16, Margin = new Thickness(20, 8, 20, 32) };
        foreach (var child in children)
            panel.Children.Add(child);
        return panel;
    }

    /// <summary>A rounded surface that stands out from the page (class "card" in App.axaml).</summary>
    public static Border Card(Control child, double padding = 16)
    {
        var card = new Border { Child = child, Padding = new Thickness(padding) };
        card.Classes.Add("card");
        return card;
    }

    /// <summary>An icon in a circle tinted with the accent color.</summary>
    public static Border IconBadge(Geometry icon, double size)
    {
        var path = new PathIcon { Data = icon, Width = size * 0.5, Height = size * 0.5 };
        path.Bind(PathIcon.ForegroundProperty, path.GetResourceObservable("AppOnTonalBrush"));
        return new Border
        {
            Width = size,
            Height = size,
            CornerRadius = new CornerRadius(size / 2),
            Child = path,
            HorizontalAlignment = HorizontalAlignment.Center,
        }.WithBackground("AppTonalBrush");
    }

    /// <summary>An icon on a rounded square tinted with its own color, for file types in lists.</summary>
    public static Border ColoredBadge(Geometry icon, Color color, double size = 44)
    {
        return new Border
        {
            Width = size,
            Height = size,
            CornerRadius = new CornerRadius(12),
            Background = new SolidColorBrush(color, 0.18),
            Child = new PathIcon { Data = icon, Width = size * 0.5, Height = size * 0.5, Foreground = new SolidColorBrush(color) },
            VerticalAlignment = VerticalAlignment.Center,
        };
    }

    /// <summary>The icon and color for a file, from its extension.</summary>
    public static (Geometry Icon, Color Color) FileKind(string name) => Path.GetExtension(name).ToLowerInvariant() switch
    {
        ".jpg" or ".jpeg" or ".png" or ".gif" or ".webp" or ".heic" or ".bmp" or ".svg" or ".tif" or ".tiff" or ".raw" or ".dng"
            => (ImageIcon, Color.FromRgb(0x2E, 0xB8, 0x72)),
        ".mp4" or ".mov" or ".mkv" or ".avi" or ".webm" or ".3gp" or ".m4v"
            => (VideoIcon, Color.FromRgb(0xE8, 0x4A, 0x6F)),
        ".mp3" or ".m4a" or ".wav" or ".flac" or ".ogg" or ".opus" or ".aac"
            => (AudioIcon, Color.FromRgb(0x9B, 0x6B, 0xF2)),
        ".zip" or ".7z" or ".rar" or ".tar" or ".gz" or ".xz" or ".bz2"
            => (ArchiveIcon, Color.FromRgb(0xE0, 0x9A, 0x1F)),
        ".pdf" => (DocumentIcon, Color.FromRgb(0xE5, 0x48, 0x3D)),
        ".doc" or ".docx" or ".odt" or ".rtf" or ".txt" or ".md" or ".xls" or ".xlsx" or ".ods" or ".csv" or ".ppt" or ".pptx" or ".odp"
            => (DocumentIcon, Color.FromRgb(0x3B, 0x82, 0xF6)),
        _ => (FileIcon, Color.FromRgb(0x7C, 0x8A, 0x9E)),
    };

    /// <summary>Uses a theme brush, following light and dark mode.</summary>
    public static T WithBackground<T>(this T control, string resourceKey) where T : Control
    {
        var property = control switch
        {
            Border => Border.BackgroundProperty,
            Panel => Panel.BackgroundProperty,
            Avalonia.Controls.Primitives.TemplatedControl => Avalonia.Controls.Primitives.TemplatedControl.BackgroundProperty,
            _ => throw new ArgumentException("No background on " + control.GetType().Name),
        };
        control.Bind(property, control.GetResourceObservable(resourceKey));
        return control;
    }
}
