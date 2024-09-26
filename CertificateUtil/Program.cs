using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace CertificateUtil;

public class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Generating issuer certificate with RSA 4096...");
        var rsa = RSA.Create(4096);
        var namebuilder = new X500DistinguishedNameBuilder();
        
        Console.Write("Common Name: ");
        var cn = Console.ReadLine();
        
        namebuilder.AddCommonName(cn);
        var request = new CertificateRequest(namebuilder.Build(), rsa, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow + TimeSpan.FromDays(36500));

        Console.Write("Export password: ");
        var password = Console.ReadLine();
        var pem = cert.Export(X509ContentType.Pfx, password);
        var str = Convert.ToBase64String(pem);

        Console.WriteLine(str);
    }
}
