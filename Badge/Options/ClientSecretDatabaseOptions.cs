using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "ClientSecretDatabase")]
public sealed class ClientSecretDatabaseOptions : IDatabaseOptions
{
    public string? TableName { get; set; }
}
