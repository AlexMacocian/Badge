using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "Certificates")]
public class CertificateServiceOptions
{
    public string? RootCA { get; set; }

    public string? RootCAPassword { get; set; }

    public string? HashAlgorithmName { get; set; }

    public string? RSASignaturePadding { get; set; }

    public string? SigningCertificateCN { get; set; }

    public TimeSpan SigningCertificateValidity { get; set; } = TimeSpan.FromDays(1);
}
