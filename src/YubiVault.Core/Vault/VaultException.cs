namespace YubiVault.Core;

public class VaultException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>None of the vault's key slots accepted the key, password or recovery code given.</summary>
public sealed class WrongKeyException(string message) : VaultException(message);
