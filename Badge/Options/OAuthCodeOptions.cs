using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "OAuth:Code")]
public sealed class OAuthCodeOptions : IDatabaseOptions
{
    public string? TableName { get; set; }
    public TimeSpan Duration { get; set; }
}
