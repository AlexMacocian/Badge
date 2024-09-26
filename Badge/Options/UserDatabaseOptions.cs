using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "Users")]
public class UserDatabaseOptions : IDatabaseOptions
{
    public string? TableName { get; set; }
}
