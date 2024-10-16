using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "OAuth:AccessToken")]
public sealed class OAuthAccessTokenOptions
{
    public TimeSpan Duration { get; set; }
}
