using Badge.Models;
using Badge.Models.Identity;
using Badge.Options;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Data.SQLite;
using System.Extensions.Core;

namespace Badge.Services.Database.Applications;

public sealed class SQLiteClientSecretDatabase : SqliteTableBase<ClientSecretDatabaseOptions>, IClientSecretDatabase
{
    private const string IdKey = "id";
    private const string DetailKey = "detail";
    private const string ApplicationIdKey = "applicationid";
    private const string CreationDateKey = "creationdate";
    private const string ExpirationDateKey = "expirationdate";
    private const string HashKey = "hash";

    private readonly ClientSecretDatabaseOptions options;
    private readonly ILogger<SQLiteClientSecretDatabase> logger;

    protected override string TableDefinition => $@"
{IdKey} TEXT PRIMARY KEY NOT NULL UNIQUE,
{ApplicationIdKey} TEXT NOT NULL,
{CreationDateKey} TEXT NOT NULL,
{ExpirationDateKey} TEXT NOT NULL,
{HashKey} TEXT NOT NULL,
{DetailKey} TEXT NOT NULL";

    public SQLiteClientSecretDatabase(
        IOptions<ClientSecretDatabaseOptions> options,
        SQLiteConnection sQLiteConnection,
        ILogger<SQLiteClientSecretDatabase> logger)
        : base(options, sQLiteConnection, logger)
    {
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<ClientSecret?> GetClientSecret(ClientSecretIdentifier clientSecretIdentifier, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.GetClientSecretInternal(clientSecretIdentifier, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while retrieving client secret");
            throw;
        }
    }

    public async Task<IEnumerable<ClientSecret>> GetClientSecrets(ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.GetClientSecretsInternal(applicationIdentifier, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while retrieving client secrets");
            throw;
        }
    }

    public async Task<bool> RemoveApplication(ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.RemoveApplicationInternal(applicationIdentifier, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while removing application");
            throw;
        }
    }

    public async Task<bool> RemoveClientSecret(ClientSecretIdentifier clientSecretIdentifier, ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.RemoveClientSecretInternal(clientSecretIdentifier, applicationIdentifier, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while removing client secret");
            throw;
        }
    }

    public async Task<bool> StoreClientSecret(ClientSecret clientSecret, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.StoreClientSecretInternal(clientSecret, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while storing client secret");
            throw;
        }
    }

    public async Task<bool> UpdateClientSecretDetail(ClientSecretIdentifier clientSecretIdentifier, ApplicationIdentifier applicationIdentifier, string detail, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.UpdateClientSecretDetailInternal(clientSecretIdentifier, applicationIdentifier, detail, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while updating client secret detail");
            throw;
        }
    }

    private async Task<bool> RemoveClientSecretInternal(ClientSecretIdentifier clientSecretIdentifier, ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken)
    {
        var query = $"DELETE FROM {this.options.TableName} WHERE {IdKey} = @id AND {ApplicationIdKey} = @appId";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", clientSecretIdentifier.ToString());
        command.Parameters.AddWithValue("@appId", applicationIdentifier.ToString());

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<bool> RemoveApplicationInternal(ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken)
    {
        var query = $"DELETE FROM {this.options.TableName} WHERE {ApplicationIdKey} = @id";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", applicationIdentifier.ToString());

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result >= 0;
    }

    private async Task<bool> StoreClientSecretInternal(ClientSecret clientSecret, CancellationToken cancellationToken)
    {
        var query = $"INSERT INTO {this.options.TableName}({IdKey}, {ApplicationIdKey}, {CreationDateKey}, {ExpirationDateKey}, {HashKey}, {DetailKey}) Values (@id, @appId, @creationDate, @expirationDate, @hash, @detail)";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", clientSecret.Id.ToString());
        command.Parameters.AddWithValue("@appId", clientSecret.ApplicationIdentifier.ToString());
        command.Parameters.AddWithValue("@creationDate", clientSecret.CreationDate.ToUniversalTime().ToString(DateTimeFormat));
        command.Parameters.AddWithValue("@expirationDate", clientSecret.ExpirationDate.ToUniversalTime().ToString(DateTimeFormat));
        command.Parameters.AddWithValue("@hash", clientSecret.Hash);
        command.Parameters.AddWithValue("@detail", clientSecret.Detail);

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<ClientSecret?> GetClientSecretInternal(ClientSecretIdentifier clientSecretIdentifier, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {this.options.TableName} WHERE {IdKey} = @id";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", clientSecretIdentifier.ToString());

        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            if (!Identifier.TryParse<ClientSecretIdentifier>(reader.GetString(0), out var secretId) ||
                secretId is null)
            {
                continue;
            }

            if (!Identifier.TryParse<ApplicationIdentifier>(reader.GetString(1), out var appId) ||
                appId is null)
            {
                continue;
            }

            var creationDate = reader.GetDateTime(2);
            var expirationDate = reader.GetDateTime(3);
            var hash = reader.GetString(4);
            var detail = reader.GetString(5);
            return new ClientSecret(secretId, appId, detail, creationDate, expirationDate, hash);
        }

        return default;
    }

    private async Task<List<ClientSecret>> GetClientSecretsInternal(ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {this.options.TableName} WHERE {ApplicationIdKey} = @id";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", applicationIdentifier.ToString());
        var secrets = new List<ClientSecret>();
        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            if (!Identifier.TryParse<ClientSecretIdentifier>(reader.GetString(0), out var secretId) ||
                secretId is null)
            {
                continue;
            }

            if (!Identifier.TryParse<ApplicationIdentifier>(reader.GetString(1), out var appId) ||
                appId is null)
            {
                continue;
            }

            var creationDate = reader.GetDateTime(2);
            var expirationDate = reader.GetDateTime(3);
            var hash = reader.GetString(4);
            var detail = reader.GetString(5);
            secrets.Add(new ClientSecret(secretId, appId, detail, creationDate, expirationDate, hash));
        }

        return secrets;
    }

    private async Task<bool> UpdateClientSecretDetailInternal(ClientSecretIdentifier clientSecretIdentifier, ApplicationIdentifier applicationIdentifier, string detail, CancellationToken cancellationToken)
    {
        var query = $"UPDATE {this.options.TableName} SET {DetailKey} = @detail WHERE {IdKey} = @id AND {ApplicationIdKey} = @appId";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@detail", detail);
        command.Parameters.AddWithValue("@id", clientSecretIdentifier.ToString());
        command.Parameters.AddWithValue("@appId", applicationIdentifier.ToString());

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }
}
