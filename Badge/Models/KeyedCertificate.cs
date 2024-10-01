using Badge.Models.Identity;
using System.Security.Cryptography.X509Certificates;

namespace Badge.Models;

public sealed class KeyedCertificate(KeyIdentifier id, X509Certificate2 certificate)
{
    public KeyIdentifier Id { get; } = id;
    public X509Certificate2 Certificate { get; } = certificate;
}
