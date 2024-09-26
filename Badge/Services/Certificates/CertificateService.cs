using Badge.Converters;
using Badge.Models;
using Badge.Options;
using Badge.Services.Database.Certificates;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Extensions;
using System.Extensions.Core;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Convert = System.Convert;

namespace Badge.Services.Certificates;

public sealed class CertificateService : ICertificateService
{
    private static X509Certificate2? SigningCertificate = default;
    private static SemaphoreSlim SemaphoreSlim = new(1);

    private readonly X509Certificate2 rootCA;
    private readonly HashAlgorithmName hashAlgorithmName;
    private readonly RSASignaturePadding signaturePadding;
    private readonly ICertificateDatabase certificateDatabase;
    private readonly CertificateServiceOptions certificateServiceOptions;
    private readonly ILogger<CertificateService> logger;

    public CertificateService(
        ICertificateDatabase certificateDatabase,
        IOptions<CertificateServiceOptions> options,
        ILogger<CertificateService> logger)
    {
        this.certificateDatabase = certificateDatabase.ThrowIfNull();
        this.certificateServiceOptions = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();

        if (this.certificateServiceOptions.RootCA is null)
        {
            throw new InvalidOperationException("No Root CA provided");
        }

        if (this.certificateServiceOptions.HashAlgorithmName is null)
        {
            throw new InvalidOperationException("No hash algorithm name provided");
        }

        if (this.certificateServiceOptions.RSASignaturePadding is null)
        {
            throw new InvalidOperationException("No RSA padding provided");
        }

        var certBytes = Convert.FromBase64String(this.certificateServiceOptions.RootCA);
        this.rootCA = new X509Certificate2(certBytes, this.certificateServiceOptions.RootCAPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        this.hashAlgorithmName = new HashAlgorithmNameTypeConverter().ConvertFrom(this.certificateServiceOptions.HashAlgorithmName!)!.Cast<HashAlgorithmName>();
        this.signaturePadding = new RSASignaturePaddingTypeConverter().ConvertFrom(this.certificateServiceOptions.RSASignaturePadding!)!.Cast<RSASignaturePadding>();
    }

    public async Task<IReadOnlyDictionary<string, X509Certificate2>> GetSigningCertificates(CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            // Call GetSigningCertificate to ensure that we have a signing certificate already generated
            _ = await GetSigningCertificate(cancellationToken);
            return await this.GetSigningCertificatesInternal(cancellationToken);
        }
        catch(Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while getting singing certificates");
            throw;
        }
    }

    public Task<X509Certificate2> GetSigningCertificate(CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return this.GetSigningCertificateInternal(cancellationToken);
        }
        catch(Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while generating certificate");
            throw;
        }
    }

    private async Task<IReadOnlyDictionary<string, X509Certificate2>> GetSigningCertificatesInternal(CancellationToken cancellationToken)
    {
        var certificates = await this.certificateDatabase.GetSigningCertificates(cancellationToken);
        if (certificates is null)
        {
            return new Dictionary<string, X509Certificate2>();
        }

        return certificates.ToDictionary(k => k.Id, k => k.Certificate);
    }

    private async Task<X509Certificate2> GetSigningCertificateInternal(CancellationToken cancellationToken)
    {
        // Try first time non-blocking
        if (SigningCertificate is X509Certificate2 signingCertificate &&
            signingCertificate.NotAfter >= DateTime.Now)
        {
            return signingCertificate;
        }

        // Block and attempt to generate a new certificate
        using var lockContext = await SemaphoreSlim.Acquire();
        // Verify that no other thread has created a new certificate in the meantime
        if (SigningCertificate is X509Certificate2 signingCertificate2 &&
            signingCertificate2.NotAfter >= DateTime.Now)
        {
            return signingCertificate2;
        }

        // Try and retrieve any stored signing certificate in the database
        var latestCertificate = await this.certificateDatabase.GetLatestSigningCertificate(cancellationToken);
        if (latestCertificate is not null &&
            latestCertificate?.Certificate.GetRSAPrivateKey() is not null)
        {
            SigningCertificate = latestCertificate.Certificate;
            return latestCertificate.Certificate;
        }

        // Generate a new signing certificate
        var certificate = this.GenerateSigningCertificate();
        var uid = Guid.NewGuid().ToString();
        var keyedCertificate = new KeyedCertificate(uid, certificate);
        if (!await this.certificateDatabase.StoreSigningCertificate(keyedCertificate, cancellationToken))
        {
            throw new InvalidOperationException("Unable to store newly generated signing certificate");
        }

        SigningCertificate = certificate;
        return certificate;
    }

    private X509Certificate2 GenerateSigningCertificate()
    {
        if (this.rootCA is null)
        {
            throw new InvalidOperationException("No Root CA has been loaded");
        }

        using var rootKey = this.rootCA.GetRSAPrivateKey();
        using var rsa = RSA.Create(4096);
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName(this.certificateServiceOptions.SigningCertificateCN!);
        var request = new CertificateRequest(
            builder.Build(),
            rsa,
            this.hashAlgorithmName,
            this.signaturePadding);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        var notBefore = DateTimeOffset.Now;
        var notAfter = notBefore.Add(this.certificateServiceOptions.SigningCertificateValidity);

        var certificate = request.Create(rootCA, notBefore, notAfter, Guid.NewGuid().ToByteArray()).CopyWithPrivateKey(rsa);        
        return certificate;
    }
}
