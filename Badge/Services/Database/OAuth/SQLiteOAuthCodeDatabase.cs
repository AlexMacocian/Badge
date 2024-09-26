using Badge.Models;
using Badge.Options;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Data.SQLite;
using System.Extensions.Core;

namespace Badge.Services.Database.OAuth;

public sealed class SQLiteOAuthCodeDatabase : SqliteTableBase<OAuthCodeDatabaseOptions>, IOAuthCodeDatabase
{
    private const string DateTimeFormat = "YYYY-MM-DD HH:MM:SS.SSS";
    private const string CodeKey = "code";
    private const string NotBeforeKey = "notbefore";
    private const string NotAfterKey = "notafter";

    private readonly OAuthCodeDatabaseOptions options;
    private readonly ILogger<SQLiteOAuthCodeDatabase> logger;

    protected override string TableDefinition => $@"
{CodeKey} TEXT PRIMARY KEY NOT NULL UNIQUE,
{NotBeforeKey} TEXT NOT NULL,
{NotAfterKey} TEXT NOT NULL";

    public SQLiteOAuthCodeDatabase(
        IOptions<OAuthCodeDatabaseOptions> options,
        SQLiteConnection sQLiteConnection,
        ILogger<SQLiteOAuthCodeDatabase> logger)
        : base(options, sQLiteConnection, logger)
    {
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<bool> CreateOAuthCode(OAuthCode code, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.CreateOAuthCodeInternal(code, cancellationToken);
        }
        catch(Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while creating OAuth code");
            throw;
        }
    }

    public async Task<OAuthCode?> GetOAuthCode(string code, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.GetOAuthCodeInternal(code, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while fetching OAuth code");
            throw;
        }
    }

    public async Task DeleteExpiredOAuthCodes(DateTime expiration, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            await this.DeleteExpiredOAuthCodesInternal(expiration, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while fetching OAuth code");
            throw;
        }
    }

    private async Task<bool> CreateOAuthCodeInternal(OAuthCode code, CancellationToken cancellationToken)
    {
        var query = $"INSERT INTO {options.TableName}({CodeKey}, {NotBeforeKey}, {NotAfterKey}) Values (@code, @notBefore, @notAfter)";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@code", code.Code);
        command.Parameters.AddWithValue("@notBefore", code.NotBefore.ToString(DateTimeFormat));
        command.Parameters.AddWithValue("@notAfter", code.NotAfter.ToString(DateTimeFormat));

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<OAuthCode?> GetOAuthCodeInternal(string code, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {this.options.TableName} WHERE {CodeKey} = '@code'";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@code", code);

        await foreach(var reader in command.ExecuteReader(cancellationToken))
        {
            var oauthCode = reader.GetString(0);
            var notBefore = reader.GetDateTime(1);
            var notAfter = reader.GetDateTime(2);
            return new OAuthCode(oauthCode, notBefore, notAfter);
        }

        return default;
    }

    private async Task DeleteExpiredOAuthCodesInternal(DateTime expiration, CancellationToken cancellationToken)
    {
        var query = $"DELETE * FROM {this.options.TableName} WHERE {NotAfterKey} < '@dateTime'";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@dateTime", expiration.ToString(DateTimeFormat));

        await command.ExecuteNonQuery(cancellationToken);
    }
}
