using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "OAuth")]
public sealed class OAuthServiceOptions
{
    public string? Issuer { get; set; }
    public List<string>? ScopesSupported { get; set; }
    public TimeSpan KeySetCacheDuration { get; set; }
    public TimeSpan AuthCodeDuration { get; set; }
}
