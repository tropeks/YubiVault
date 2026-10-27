using YubiVault.Core.Keys;

namespace YubiVault.Core.Tests;

public class RecoveryCodeTests
{
    [Fact]
    public void FormatsAsEightGroupsOfFour()
    {
        string text = RecoveryCode.Format(RecoveryCode.Generate());
        Assert.Matches("^([A-Z2-9]{4}-){7}[A-Z2-9]{4}$", text);
    }

    [Fact]
    public void ParsesWhatItFormats()
    {
        var code = RecoveryCode.Generate();
        Assert.Equal(code, RecoveryCode.Parse(RecoveryCode.Format(code)));
    }

    [Fact]
    public void ParsingIgnoresCaseSpacesAndDashes()
    {
        var code = RecoveryCode.Generate();
        string sloppy = RecoveryCode.Format(code).ToLowerInvariant().Replace("-", " ");
        Assert.Equal(code, RecoveryCode.Parse(sloppy));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ABCD")]
    [InlineData("ABCD-ABCD-ABCD-ABCD-ABCD-ABCD-ABCD-ABC0")]
    [InlineData("ABCD-ABCD-ABCD-ABCD-ABCD-ABCD-ABCD-ABCD-A")]
    public void RejectsInvalidCodes(string text) => Assert.Throws<FormatException>(() => RecoveryCode.Parse(text));
}
