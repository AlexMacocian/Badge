using Badge.Models;
using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "OAuth")]
public sealed class OAuthServiceOptions
{
    public string? Issuer { get; set; }
    public List<OAuthScope>? ScopesSupported { get; set; }
    public List<string>? GrantTypesSupported { get; set; }
    public TimeSpan KeySetCacheDuration { get; set; }
    public OAuthCodeOptions? Code { get; set; }
    public OAuthRefreshTokenOptions? RefreshToken { get; set; }
    public OAuthAccessTokenOptions? AccessToken { get; set; }
    public OAuthOpenIdTokenOptions? OpenIdToken { get; set; }
}