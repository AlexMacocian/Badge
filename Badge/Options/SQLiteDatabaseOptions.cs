using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "SQLiteDatabase")]
public sealed class SQLiteDatabaseOptions
{
    public string? ConnectionString { get; set; }
}
