using System.Security.Cryptography.X509Certificates;

namespace Badge.Models;

public sealed class KeyedCertificate(string id, X509Certificate2 certificate)
{
    public string Id { get; } = id;
    public X509Certificate2 Certificate { get; } = certificate;
}
