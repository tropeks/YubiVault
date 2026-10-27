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
    public static readonly Geometry PlusIcon = Geometry.Parse("M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z");

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

    /// <summary>A full-width button, accent-colored for the main action of a page.</summary>
    public static Button Button(string text, Action onClick, bool accent = false, Geometry? icon = null)
    {
        object content = text;
        if (icon is not null)
        {
            content = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 10,
                Children = { new PathIcon { Data = icon, Width = 18, Height = 18 }, new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center } },
            };
        }
        var button = new Button
        {
            Content = content,
            MinHeight = TouchSize,
            FontSize = 16,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Center,
            VerticalContentAlignment = VerticalAlignment.Center,
        };
        if (accent)
            button.Classes.Add("accent");
        button.Click += (_, _) => onClick();
        return button;
    }

    /// <summary>A borderless square button with an icon, for top bars and list rows.</summary>
    public static Button IconButton(Geometry icon, string label, Action? onClick = null)
    {
        var button = new Button
        {
            Content = new PathIcon { Data = icon, Width = 22, Height = 22 },
            Width = TouchSize,
            Height = TouchSize,
            Padding = new Thickness(0),
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            HorizontalContentAlignment = HorizontalAlignment.Center,
            VerticalContentAlignment = VerticalAlignment.Center,
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
            MinHeight = 56,
            Margin = new Thickness(4, 4, 4, 0),
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
            Margin = new Thickness(back is null ? 12 : 4, 0, 4, 0),
            Children = { new TextBlock { Text = title, FontSize = 20, FontWeight = FontWeight.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis } },
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
        var panel = new StackPanel { Spacing = 14, Margin = new Thickness(16, 8, 16, 24) };
        foreach (var child in children)
            panel.Children.Add(child);
        return panel;
    }

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
