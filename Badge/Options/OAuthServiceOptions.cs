using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "OAuth")]
public sealed class OAuthServiceOptions
{
    public TimeSpan KeySetCacheDuration { get; set; }
    public TimeSpan AuthCodeDuration { get; set; }
}
