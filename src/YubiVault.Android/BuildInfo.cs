namespace YubiVault.Android;

/// <summary>Which channel this build is for: GitHub Releases (updates itself) or Google Play (built with -p:PlayStore=true).</summary>
static class BuildInfo
{
#if PLAY_STORE
    public const bool IsPlayStore = true;
#else
    public const bool IsPlayStore = false;
#endif
}
