using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using YubiVault.Core.Keys;
using YubiVault.Core;
using YubiVault.YubiKey;

namespace YubiVault.Cli;

static class Program
{
    const string Usage = """
        YubiVault: encrypt files and folders with your YubiKey.

        Usage:
          yubivault-cli init <vault> [--otp [--no-password] [--program-slot]]
          yubivault-cli add <vault> <file-or-folder>... [--to <vault-folder>]
          yubivault-cli list <vault>
          yubivault-cli extract <vault> <vault-path> <destination> [--overwrite]
          yubivault-cli remove <vault> <vault-path>
          yubivault-cli keys <vault>
          yubivault-cli add-key <vault> [--otp [--no-password] [--program-slot]]
          yubivault-cli remove-key <vault> <slot-id>
          yubivault-cli new-recovery-code <vault>
          yubivault-cli compact <vault>
          yubivault-cli hide <vault> <size>
          yubivault-cli pad <vault> <size>

        <vault> is the vault file; ".yvault" is added to the name if it has no extension.
        By default the vault is protected by a FIDO2 security key (any YubiKey 5 or Security Key):
        Windows asks for the key's PIN and a touch.

        Options:
          --recovery       Unlock with the recovery code instead of a key.
          --otp            Use YubiKey 5 OTP challenge-response (slot 2) instead of FIDO2.
          --program-slot   With --otp: program slot 2 with a new secret, even if it is in use.
          --no-password    With --otp: use the YubiKey alone, without a password.
          --hidden         Work in the hidden vault inside <vault>: asks its password and your
                           security key (or, with --recovery, the hidden vault's recovery code).

        Hidden vault:
          "hide" creates a hidden vault of <size> (e.g. 200M, 1G) inside the vault file, opened by
          its own password and your security key. It lives in random padding that looks the same
          as the padding "pad" adds, so without its password nobody can tell it exists. Both
          commands rewrite the padding and DESTROY any hidden vault already in the file.

        Use "/" as <vault-path> to extract everything.
        """;

    static int Main(string[] args)
    {
        try
        {
            var cli = Arguments.Parse(args);
            if (cli.Command is null or "help" || cli.Flags.Contains("--help"))
            {
                Console.WriteLine(Usage);
                return cli.Command is null ? 1 : 0;
            }
            return Run(cli);
        }
        catch (Exception e) when (e is VaultException or ArgumentException or FormatException or IOException
                                      or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine($"Error: {e.Message}");
            return 2;
        }
    }

    static readonly HashSet<string> Commands =
        ["init", "add", "list", "extract", "remove", "keys", "add-key", "remove-key", "new-recovery-code", "compact", "hide", "pad"];

    static int Run(Arguments cli)
    {
        if (!Commands.Contains(cli.Command!))
            throw new ArgumentException($"Unknown command \"{cli.Command}\". Run \"yubivault-cli help\".");
        switch (cli.Command)
        {
            case "init":
                return Init(VaultFilePath(cli.Positional(0, "vault")), cli);
        }

        using var vault = Unlock(VaultFilePath(cli.Positional(0, "vault")), cli);
        switch (cli.Command)
        {
            case "add":
                var sources = cli.PositionalFrom(1, "file-or-folder");
                string target = cli.Option("--to") ?? "";
                int added = sources.Sum(s => vault.Add(s, target, Progress("Encrypting")));
                Console.WriteLine($"Added {added} file(s).");
                return 0;

            case "list":
                foreach (var entry in vault.Entries.OrderBy(e => e.Path, StringComparer.OrdinalIgnoreCase))
                    Console.WriteLine($"{FormatSize(entry.Size),10}  {entry.ModifiedUtc.ToLocalTime():yyyy-MM-dd HH:mm}  {entry.Path}");
                Console.WriteLine($"{vault.Entries.Count} file(s), {FormatSize(vault.Entries.Sum(e => e.Size))}.");
                if (vault.HiddenFreeBytes is long free)
                    Console.WriteLine($"Hidden vault: {FormatSize(free)} free of {FormatSize(vault.HiddenCapacity!.Value)}.");
                return 0;

            case "extract":
                int extracted = vault.Extract(cli.Positional(1, "vault-path"), cli.Positional(2, "destination"),
                    cli.Flags.Contains("--overwrite"), Progress("Decrypting"));
                Console.WriteLine($"Extracted {extracted} file(s).");
                return 0;

            case "remove":
                int removed = vault.Remove(cli.Positional(1, "vault-path"));
                Console.WriteLine($"Removed {removed} file(s).");
                return 0;

            case "keys":
                foreach (var slot in vault.Slots)
                {
                    string extra = slot.RequiresPassword ? ", with password" : "";
                    Console.WriteLine($"{slot.Id,-4} {slot.Label}{extra}  (added {slot.CreatedUtc.ToLocalTime():yyyy-MM-dd})");
                }
                return 0;

            case "add-key":
                Console.WriteLine("Insert the new key (and remove the others).");
                KeySlot added2;
                if (cli.Flags.Contains("--otp"))
                {
                    added2 = vault.AddYubiKey(PrepareYubiKey(cli), AskNewPassword(cli));
                }
                else
                {
                    Console.WriteLine("You will be asked for the key's PIN and a touch, twice.");
                    added2 = vault.AddSecurityKey(SecurityKey());
                }
                Console.WriteLine($"Registered {added2.Label} as {added2.Id}.");
                return 0;

            case "remove-key":
                vault.RemoveSlot(cli.Positional(1, "slot-id"));
                Console.WriteLine("Key removed.");
                return 0;

            case "new-recovery-code":
                ShowRecoveryCode(vault.RegenerateRecoveryCode());
                return 0;

            case "compact":
                long before = vault.FileSize;
                vault.Compact();
                if (vault.IsHidden)
                    Console.WriteLine($"Hidden vault: {FormatSize(vault.HiddenFreeBytes!.Value)} free.");
                else
                    Console.WriteLine($"Vault file: {FormatSize(before)} -> {FormatSize(vault.FileSize)}.");
                return 0;

            case "hide":
                long hiddenSize = ParseSize(cli.Positional(1, "size"));
                if (!Confirm("This replaces the vault's padding and destroys any hidden vault already in it. Continue?"))
                    throw new VaultException("Cancelled.");
                string hiddenPassword = AskHiddenPassword();
                Console.WriteLine("Creating the hidden vault. You will be asked for your security key's PIN and a touch, twice.");
                string hiddenRecovery = vault.CreateHiddenVault(hiddenPassword, SecurityKey(), hiddenSize);
                Console.WriteLine($"Hidden vault created ({FormatSize(hiddenSize)}). Open it with --hidden.");
                ShowRecoveryCode(hiddenRecovery);
                return 0;

            case "pad":
                long padding = ParseSize(cli.Positional(1, "size"));
                if (vault.Padding > 0 && !Confirm("This replaces the vault's padding and destroys any hidden vault in it. Continue?"))
                    throw new VaultException("Cancelled.");
                vault.SetPadding(padding);
                Console.WriteLine($"Vault file: {FormatSize(vault.FileSize)}.");
                return 0;

            default:
                throw new ArgumentException($"Unknown command \"{cli.Command}\". Run \"yubivault-cli help\".");
        }
    }

    /// <summary>Adds the vault extension to a name without one.</summary>
    static string VaultFilePath(string path) =>
        Path.HasExtension(path) || Directory.Exists(path) ? path : path + Vault.FileExtension;

    static int Init(string path, Arguments cli)
    {
        Vault vault;
        string recoveryCode;
        if (cli.Flags.Contains("--otp"))
        {
            var key = PrepareYubiKey(cli);
            string? password = AskNewPassword(cli);
            Console.WriteLine("Creating the vault...");
            (vault, recoveryCode) = Vault.Create(path, key, password);
        }
        else
        {
            var securityKey = SecurityKey();
            Console.WriteLine("Creating the vault. You will be asked for your security key's PIN and a touch, twice.");
            (vault, recoveryCode) = Vault.Create(path, securityKey);
        }
        using (vault)
        {
            Console.WriteLine($"Vault created: {vault.FilePath}");
            ShowRecoveryCode(recoveryCode);
        }
        return 0;
    }

    static Vault Unlock(string path, Arguments cli)
    {
        if (!Vault.Exists(path))
            throw new VaultException($"No vault found at {Path.GetFullPath(path)}.");
        if (cli.Flags.Contains("--hidden"))
        {
            if (cli.Flags.Contains("--recovery"))
            {
                Console.Write("Hidden vault recovery code: ");
                return Vault.OpenHiddenWithRecoveryCode(path, Console.ReadLine() ?? "");
            }
            string password = ReadSecret("Hidden vault password: ");
            return Vault.OpenHidden(path, password, SecurityKey());
        }
        if (cli.Flags.Contains("--recovery"))
        {
            Console.Write("Recovery code: ");
            return Vault.OpenWithRecoveryCode(path, Console.ReadLine() ?? "");
        }
        var slots = Vault.ReadKeySlots(path);
        bool hasFido2 = slots.Any(s => s.Type == KeySlotType.Fido2);
        bool hasOtp = slots.Any(s => s.Type == KeySlotType.YubiKey);
        if (hasFido2 && !(hasOtp && OtpKeyConnected()))
        {
            Console.WriteLine(OperatingSystem.IsWindows() ? "Windows will ask for your security key's PIN and a touch." : "Unlocking with your security key.");
            return Vault.OpenWithFido2(path, SecurityKey());
        }
        var key = FindYubiKey();
        return Vault.OpenWithYubiKey(path, key, () => ReadSecret("Password: "));
    }

    static bool OtpKeyConnected()
    {
        try
        {
            return YubiKeyResponder.FindAll().Count > 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    static IFido2Authenticator SecurityKey()
    {
#if DEBUG
        if (Environment.GetEnvironmentVariable("YUBIVAULT_FAKE_YUBIKEY") is { Length: > 0 } fake)
            return new FakeSecurityKey(fake);
#endif
        if (!OperatingSystem.IsWindows())
        {
            return new YubicoSecurityKey
            {
                AskPin = retries => ReadSecret(retries is int left ? $"Wrong PIN, {left} tries left. PIN: " : "Security key PIN: "),
                TouchNotifier = waiting => { if (waiting) Console.WriteLine("Touch your security key..."); },
            };
        }
        if (!WindowsSecurityKey.IsSupported(out string reason))
            throw new VaultException(reason);
        IntPtr window = GetConsoleWindow();
        return new WindowsSecurityKey(window != IntPtr.Zero ? window : GetForegroundWindow());
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();

    static IChallengeResponder FindYubiKey()
    {
#if DEBUG
        // Development only: a software stand-in for a YubiKey, so the CLI can be exercised without hardware.
        if (Environment.GetEnvironmentVariable("YUBIVAULT_FAKE_YUBIKEY") is { Length: > 0 } fake)
            return new FakeYubiKey(fake);
#endif
        var keys = YubiKeyResponder.FindAll();
        if (keys.Count == 0)
            throw new VaultException(NoYubiKeyMessage);
        if (keys.Count > 1)
            throw new VaultException("More than one YubiKey is connected. Leave only one plugged in.");
        keys[0].TouchNotifier = () => Console.WriteLine("Touch your YubiKey...");
        return keys[0];
    }

    const string NoYubiKeyMessage = """
        No YubiKey with OTP found. Plug in your YubiKey, or use --recovery.
        Security Key and YubiKey Bio models have no OTP: create vaults without --otp to use FIDO2.
        On a YubiKey 5, OTP may be turned off; turn it on from an administrator PowerShell and replug:
            ykman config usb --enable OTP
        """;

    static IChallengeResponder PrepareYubiKey(Arguments cli)
    {
        var key = FindYubiKey();
        if (key is not YubiKeyResponder yubiKey)
            return key;
        bool configured = yubiKey.IsSlotConfigured;
        if (configured && !cli.Flags.Contains("--program-slot"))
        {
            Console.WriteLine("Slot 2 of this YubiKey is already configured; YubiVault will use it as is.");
            Console.WriteLine("(It must be in HMAC-SHA1 challenge-response mode. Use --program-slot to replace it.)");
            return yubiKey;
        }
        if (configured && !Confirm("This will ERASE the current contents of slot 2 on your YubiKey. Continue?"))
            throw new VaultException("Cancelled.");
        Console.WriteLine("Programming slot 2 with a new HMAC-SHA1 secret (touch required)...");
        yubiKey.ProgramSlot();
        return yubiKey;
    }

    static string? AskNewPassword(Arguments cli)
    {
        if (cli.Flags.Contains("--no-password"))
            return null;
        Console.WriteLine("Choose a password to use together with the YubiKey (leave empty for none).");
        while (true)
        {
            string password = ReadSecret("Password: ");
            if (password.Length == 0)
                return null;
            if (ReadSecret("Repeat password: ") == password)
                return password;
            Console.WriteLine("The passwords do not match. Try again.");
        }
    }

    static string AskHiddenPassword()
    {
        Console.WriteLine("Choose the hidden vault's password. It must differ from anything that opens the outer vault.");
        while (true)
        {
            string password = ReadSecret("Hidden vault password: ");
            if (password.Length < 8)
                Console.WriteLine("Use at least 8 characters.");
            else if (ReadSecret("Repeat password: ") == password)
                return password;
            else
                Console.WriteLine("The passwords do not match. Try again.");
        }
    }

    /// <summary>Parses sizes like 500K, 200M, 1.5G (binary units) or plain bytes.</summary>
    static long ParseSize(string text)
    {
        text = text.Trim().ToUpperInvariant().TrimEnd('B');
        long unit = text.EndsWith('K') ? 1L << 10 : text.EndsWith('M') ? 1L << 20 : text.EndsWith('G') ? 1L << 30 : 1;
        if (unit > 1)
            text = text[..^1];
        if (!double.TryParse(text, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double value)
            || value < 0)
            throw new ArgumentException($"Not a size: \"{text}\". Use e.g. 200M or 1G.");
        return (long)(value * unit);
    }

    static void ShowRecoveryCode(string code)
    {
        Console.WriteLine();
        Console.WriteLine("RECOVERY CODE (shown only once):");
        Console.WriteLine();
        Console.WriteLine($"    {code}");
        Console.WriteLine();
        Console.WriteLine("Write it down or print it and keep it somewhere safe. It opens the vault");
        Console.WriteLine("if you lose your key. Anyone who has it can open the vault.");
    }

    static string ReadSecret(string prompt)
    {
        Console.Write(prompt);
        if (Console.IsInputRedirected)
            return Console.ReadLine() ?? "";
        var text = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (text.Length > 0)
                    text.Length--;
            }
            else if (!char.IsControl(key.KeyChar))
            {
                text.Append(key.KeyChar);
            }
        }
        Console.WriteLine();
        return text.ToString();
    }

    static bool Confirm(string question)
    {
        Console.Write($"{question} [y/N] ");
        return (Console.ReadLine() ?? "").Trim().Equals("y", StringComparison.OrdinalIgnoreCase);
    }

    static IProgress<string> Progress(string verb) => new SyncProgress(path => Console.WriteLine($"  {verb} {path}"));

    static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.0} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.0} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.0} GB",
    };

    sealed class SyncProgress(Action<string> report) : IProgress<string>
    {
        public void Report(string value) => report(value);
    }

#if DEBUG
    sealed class FakeSecurityKey(string secret) : IFido2Authenticator
    {
        public string Description => "Fake security key (debug)";

        public byte[] MakeCredential(string relyingPartyId, byte[] userId, string userName) =>
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), userId);

        public (byte[] CredentialId, byte[] Secret) GetSecret(string relyingPartyId, IReadOnlyList<(byte[] CredentialId, byte[] Salt)> credentials)
        {
            var (id, salt) = credentials[0];
            return (id, HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret + Convert.ToBase64String(id)), salt));
        }
    }

    sealed class FakeYubiKey(string secret) : IChallengeResponder
    {
        public int? SerialNumber => null;
        public string Description => "Fake YubiKey (debug)";
        public byte[] Respond(byte[] challenge) => HMACSHA1.HashData(Encoding.UTF8.GetBytes(secret), challenge);
    }
#endif
}
