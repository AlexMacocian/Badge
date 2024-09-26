using Badge.Models;

namespace Badge.Services.Database.Certificates;

public interface ICertificateDatabase
{
    Task<KeyedCertificate?> GetLatestSigningCertificate(CancellationToken cancellationToken);
    Task<List<KeyedCertificate>> GetSigningCertificates(CancellationToken cancellationToken);
    Task<bool> StoreSigningCertificate(KeyedCertificate certificate, CancellationToken cancellationToken);
}
