using System.Security.Cryptography.X509Certificates;

namespace Badge.Services.Certificates;

public interface ICertificateService
{
    Task<IReadOnlyDictionary<string, X509Certificate2>> GetSigningCertificates(CancellationToken cancellationToken);
    Task<X509Certificate2> GetSigningCertificate(CancellationToken cancellationToken);
}
