namespace YubiVault.Cli;

/// <summary>Minimal parser: a command, positional arguments, "--flag" switches and "--option value" pairs.</summary>
sealed class Arguments
{
    static readonly HashSet<string> OptionsWithValue = ["--to"];

    public string? Command { get; private init; }
    public HashSet<string> Flags { get; } = [];
    readonly Dictionary<string, string> _options = [];
    readonly List<string> _positional = [];

    public static Arguments Parse(string[] args)
    {
        var result = new Arguments { Command = args.Length > 0 ? args[0].ToLowerInvariant() : null };
        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];
            if (OptionsWithValue.Contains(arg))
            {
                if (i + 1 >= args.Length)
                    throw new ArgumentException($"{arg} needs a value.");
                result._options[arg] = args[++i];
            }
            else if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                result.Flags.Add(arg);
            }
            else
            {
                result._positional.Add(arg);
            }
        }
        return result;
    }

    public string? Option(string name) => _options.GetValueOrDefault(name);

    public string Positional(int index, string name) =>
        index < _positional.Count ? _positional[index] : throw new ArgumentException($"Missing <{name}>. Run \"yubivault help\".");

    public IReadOnlyList<string> PositionalFrom(int index, string name) =>
        index < _positional.Count ? _positional.Skip(index).ToList() : throw new ArgumentException($"Missing <{name}>. Run \"yubivault help\".");
}
