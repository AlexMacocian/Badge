using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "OAuth:RefreshToken")]
public sealed class OAuthRefreshTokenOptions : IDatabaseOptions
{
    public string? TableName { get; set; }
    public TimeSpan Duration { get; set; }
}
