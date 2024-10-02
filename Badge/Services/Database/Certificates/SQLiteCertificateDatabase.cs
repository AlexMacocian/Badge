using Badge.Models;
using Badge.Models.Identity;
using Badge.Options;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Data.SQLite;
using System.Extensions.Core;
using System.Security.Cryptography.X509Certificates;

namespace Badge.Services.Database.Certificates;

public sealed class SQLiteCertificateDatabase : SqliteTableBase<CertificateDatabaseOptions>, ICertificateDatabase
{
    private const string UseSigning = "signing";

    private const string IdKey = "id";
    private const string CertificateKey = "certificate";
    private const string NotBeforeKey = "notbefore";
    private const string NotAfterKey = "notafter";
    private const string ThumbprintKey = "thumbprint";
    private const string UseKey = "use";

    private readonly CertificateDatabaseOptions options;
    private readonly ILogger<SQLiteCertificateDatabase> logger;

    protected override string TableDefinition => $@"
{IdKey} TEXT PRIMARY KEY NOT NULL UNIQUE,
{CertificateKey} TEXT NOT NULL,
{NotBeforeKey} TEXT NOT NULL,
{NotAfterKey} TEXT NOT NULL,
{ThumbprintKey} TEXT NOT NULL,
{UseKey} TEXT NOT NULL";

    public SQLiteCertificateDatabase(IOptions<CertificateDatabaseOptions> options, SQLiteConnection sQLiteConnection, ILogger<SQLiteCertificateDatabase> logger)
        : base(options, sQLiteConnection, logger)
    {
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<KeyedCertificate?> GetLatestSigningCertificate(CancellationToken cancellationToken)
    {
        var scopedLogger = logger.CreateScopedLogger();
        try
        {
            return await GetLatestSigningCertificateInternal(cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while getting latest signing certificate");
            throw;
        }
    }

    public async Task<List<KeyedCertificate>> GetSigningCertificates(CancellationToken cancellationToken)
    {
        var scopedLogger = logger.CreateScopedLogger();
        try
        {
            return await GetSigningCertificatesInternal(cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while getting signing certificates");
            throw;
        }
    }

    public async Task<bool> StoreSigningCertificate(KeyedCertificate certificate, CancellationToken cancellationToken)
    {
        var scopedLogger = logger.CreateScopedLogger();
        try
        {
            return await StoreSigningCertificateInternal(certificate, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while storing certificate");
            throw;
        }
    }

    private async Task<List<KeyedCertificate>> GetSigningCertificatesInternal(CancellationToken cancellationToken)
    {
        var certificateList = new List<KeyedCertificate>();
        var query = $"SELECT {IdKey}, {CertificateKey} FROM {options.TableName} WHERE {UseKey} = '{UseSigning}'";
        using var command = await GetCommand(query, cancellationToken);
        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(0);
            if (!Identifier.TryParse<KeyIdentifier>(id, out var keyId) ||
                keyId is null)
            {
                continue;
            }

            var certificateBase64 = reader.GetString(1);
            var certificate = new X509Certificate2(Convert.FromBase64String(certificateBase64), (string?)default, X509KeyStorageFlags.PersistKeySet);
            certificateList.Add(new KeyedCertificate(keyId, certificate));
        }

        return certificateList;
    }

    private async Task<KeyedCertificate?> GetLatestSigningCertificateInternal(CancellationToken cancellationToken)
    {
        var query = $"SELECT {IdKey}, {CertificateKey} FROM {options.TableName} WHERE {UseKey} = '{UseSigning}' AND {NotBeforeKey} = (SELECT MAX ({NotBeforeKey}) FROM {options.TableName})";
        using var command = await GetCommand(query, cancellationToken);
        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(0);
            if (!Identifier.TryParse<KeyIdentifier>(id, out var keyId) ||
                keyId is null)
            {
                continue;
            }

            var certificateBase64 = reader.GetString(1);
            var certificate = new X509Certificate2(Convert.FromBase64String(certificateBase64), (string?)default, X509KeyStorageFlags.PersistKeySet);
            return new KeyedCertificate(keyId, certificate);
        }

        return default;
    }

    private async Task<bool> StoreSigningCertificateInternal(KeyedCertificate certificate, CancellationToken cancellationToken)
    {
        var query = $"INSERT INTO {options.TableName}({IdKey}, {CertificateKey}, {NotBeforeKey}, {NotAfterKey}, {ThumbprintKey}, {UseKey}) Values (@id, @certificate, @notBefore, @notAfter, @thumbprint, @use)";
        var rawCert = Convert.ToBase64String(certificate.Certificate.Export(X509ContentType.Pkcs12));
        using var command = await GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", certificate.Id.ToString());
        command.Parameters.AddWithValue("@certificate", rawCert);
        command.Parameters.AddWithValue("@notBefore", certificate.Certificate.NotBefore.ToUniversalTime().ToString(DateTimeFormat));
        command.Parameters.AddWithValue("@notAfter", certificate.Certificate.NotAfter.ToUniversalTime().ToString(DateTimeFormat));
        command.Parameters.AddWithValue("@thumbprint", certificate.Certificate.Thumbprint);
        command.Parameters.AddWithValue("@use", UseSigning);

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }
}
