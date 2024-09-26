using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "OAuth")]
public class OAuthCodeDatabaseOptions : IDatabaseOptions
{
    public string? TableName { get; set; } = "oauth_codes";
}
