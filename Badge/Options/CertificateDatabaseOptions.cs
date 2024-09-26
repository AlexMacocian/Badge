using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "Certificates")]
public sealed class CertificateDatabaseOptions : IDatabaseOptions
{
    public string? TableName { get; set; } = "certificates";
}
