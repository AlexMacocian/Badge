using Badge.Models;
using Badge.Options;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Data.SQLite;
using System.Extensions;
using System.Extensions.Core;

namespace Badge.Services.Database.OAuth;

public class SQLiteOAuthRefreshTokenDatabase : SqliteTableBase<OAuthRefreshTokenOptions>, IOAuthRefreshTokenDatabase
{
    private const string TokenKey = "token";
    private const string NotAfterKey = "notafter";

    private readonly OAuthRefreshTokenOptions options;
    private readonly ILogger<SQLiteOAuthRefreshTokenDatabase> logger;

    protected override string TableDefinition => $@"
{TokenKey} TEXT PRIMARY KEY NOT NULL UNIQUE,
{NotAfterKey} TEXT NOT NULL";

    public SQLiteOAuthRefreshTokenDatabase(
        IOptions<OAuthRefreshTokenOptions> options,
        SQLiteConnection sQLiteConnection,
        ILogger<SQLiteOAuthRefreshTokenDatabase> logger) : base(options, sQLiteConnection, logger)
    {
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<bool> CreateRefreshToken(string token, DateTime expirationTime, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.CreateRefreshTokenInternal(token, expirationTime, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while creating refresh token");
            throw;
        }
    }

    public async Task<bool> ValidateRefreshToken(string token, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.ValidateRefreshTokenInternal(token, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while validating refresh token");
            throw;
        }
    }

    public async Task<bool> DeleteRefreshToken(string token, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.DeleteRefreshTokenInternal(token, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while deleting refresh token");
            throw;
        }
    }

    public async Task DeleteExpiredOAuthCodes(DateTime expiration, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            await this.DeleteExpiredRefreshTokensInternal(expiration, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while deleting expired refresh tokens");
            throw;
        }
    }

    private async Task<bool> CreateRefreshTokenInternal(string token, DateTime expirationTime, CancellationToken cancellationToken)
    {
        var query = $"INSERT INTO {options.TableName}({TokenKey}, {NotAfterKey}) Values (@token, @notAfter)";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@token", token);
        command.Parameters.AddWithValue("@notAfter", expirationTime.ToUniversalTime().ToString(DateTimeFormat));

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<bool> ValidateRefreshTokenInternal(string token, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {this.options.TableName} WHERE {TokenKey} = '@token'";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@token", token);

        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            var readToken = reader.GetString(0);
            var notAfter = reader.GetDateTime(1);
            if (!Enum.TryParse<CodeChallengeMethods>(reader.GetString(7), true, out var codeChallengeMethod))
            {
                throw new InvalidOperationException($"Unable to parse {codeChallengeMethod} as {nameof(CodeChallengeMethods)}");
            }

            return readToken == token && notAfter < DateTime.UtcNow;
        }

        return false;
    }

    private async Task<bool> DeleteRefreshTokenInternal(string token, CancellationToken cancellationToken)
    {
        var query = $"DELETE * FROM {options.TableName} WHERE {TokenKey} = '@token'";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@token", token);

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task DeleteExpiredRefreshTokensInternal(DateTime expiration, CancellationToken cancellationToken)
    {
        var query = $"DELETE * FROM {this.options.TableName} WHERE {NotAfterKey} < '@dateTime'";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@dateTime", expiration.ToUniversalTime().ToString(DateTimeFormat));

        await command.ExecuteNonQuery(cancellationToken);
    }
}
