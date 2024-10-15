using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "OAuth")]
public class OAuthTokenDatabaseOptions : IDatabaseOptions
{
    public string? TableName { get; set; } = "oauth_tokens";
}
