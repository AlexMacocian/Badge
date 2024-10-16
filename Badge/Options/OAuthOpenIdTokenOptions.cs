using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "OAuth:OpenIdToken")]
public sealed class OAuthOpenIdTokenOptions
{
    public TimeSpan Duration { get; set; }
}
