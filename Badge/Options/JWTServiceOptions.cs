using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "JWT")]
public class JWTServiceOptions
{
    public string SigningAlgorithm { get; set; } = "RS512";
    public string Issuer { get; set; } = "badge.service";
    public string Audience { get; set; } = "badge.service";
}
