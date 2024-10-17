using Badge.Models;
using Badge.Models.Identity;
using Badge.Options;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Data.SQLite;
using System.Extensions.Core;

namespace Badge.Services.Database.OAuth;

public sealed class SQLiteOAuthCodeDatabase : SqliteTableBase<OAuthCodeOptions>, IOAuthCodeDatabase
{
    private const string CodeKey = "code";
    private const string NotBeforeKey = "notbefore";
    private const string NotAfterKey = "notafter";
    private const string UsernameKey = "username";
    private const string ScopeKey = "scope";
    private const string RedirectUriKey = "redirect";
    private const string CodeChallengeKey = "codechallenge";
    private const string CodeChallengeMethodKey = "codechallengemethod";
    private const string ClientIdKey = "clientid";
    private const string UserIdKey = "userid";
    private const string StateKey = "state";

    private readonly OAuthCodeOptions options;
    private readonly ILogger<SQLiteOAuthCodeDatabase> logger;

    protected override string TableDefinition => $@"
{CodeKey} TEXT PRIMARY KEY NOT NULL UNIQUE,
{NotBeforeKey} TEXT NOT NULL,
{NotAfterKey} TEXT NOT NULL,
{UsernameKey} TEXT NOT NULL,
{ScopeKey} TEXT NOT NULL,
{RedirectUriKey} TEXT NOT NULL,
{CodeChallengeKey} TEXT NOT NULL,
{CodeChallengeMethodKey} TEXT NOT NULL,
{ClientIdKey} TEXT NOT NULL,
{UserIdKey} TEXT NOT NULL,
{StateKey} TEXT NOT NULL";

    public SQLiteOAuthCodeDatabase(
        IOptions<OAuthCodeOptions> options,
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

    public async Task<bool> ExpireOAuthCode(string code, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.ExpireOAuthCodeInternal(code, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while expiring OAuth code");
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

    private async Task<bool> ExpireOAuthCodeInternal(string code, CancellationToken cancellationToken)
    {
        var query = $"UPDATE {this.options.TableName} SET {NotAfterKey} = @notAfter WHERE {CodeKey} = @code";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@code", code);
        command.Parameters.AddWithValue("@notAfter", DateTime.UtcNow.ToString(DateTimeFormat));

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<bool> CreateOAuthCodeInternal(OAuthCode code, CancellationToken cancellationToken)
    {
        var query = $"INSERT INTO {options.TableName}({CodeKey}, {NotBeforeKey}, {NotAfterKey}, {UsernameKey}, {ScopeKey}, {RedirectUriKey}, {CodeChallengeKey}, {CodeChallengeMethodKey}, {ClientIdKey}, {UserIdKey}, {StateKey}) Values (@code, @notBefore, @notAfter, @username, @scope, @redirect, @codeChallenge, @codeChallengeMethod, @clientId, @userId, @state)";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@code", code.Code);
        command.Parameters.AddWithValue("@notBefore", code.NotBefore.ToUniversalTime().ToString(DateTimeFormat));
        command.Parameters.AddWithValue("@notAfter", code.NotAfter.ToUniversalTime().ToString(DateTimeFormat));
        command.Parameters.AddWithValue("@username", code.Username);
        command.Parameters.AddWithValue("@scope", code.Scope);
        command.Parameters.AddWithValue("@redirect", code.Redirect);
        command.Parameters.AddWithValue("@codeChallenge", code.CodeChallenge ?? "none");
        command.Parameters.AddWithValue("@codeChallengeMethod", code.CodeChallengeMethod);
        command.Parameters.AddWithValue("@clientId", code.ClientId.ToString());
        command.Parameters.AddWithValue("@userId", code.UserId.ToString());
        command.Parameters.AddWithValue("@state", code.State);

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<OAuthCode?> GetOAuthCodeInternal(string code, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {this.options.TableName} WHERE {CodeKey} = @code";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@code", code);

        await foreach(var reader in command.ExecuteReader(cancellationToken))
        {
            var oauthCode = reader.GetString(0);
            var notBefore = reader.GetDateTime(1);
            var notAfter = reader.GetDateTime(2);
            var username = reader.GetString(3);
            var scope = reader.GetString(4);
            var redirect = reader.GetString(5);
            var codeChallenge = reader.GetString(6);
            var state = reader.GetString(10);
            if (!Enum.TryParse<CodeChallengeMethods>(reader.GetString(7), true, out var codeChallengeMethod))
            {
                throw new InvalidOperationException($"Unable to parse {codeChallengeMethod} as {nameof(CodeChallengeMethods)}");
            }

            if (!Identifier.TryParse<ApplicationIdentifier>(reader.GetString(8), out var clientIdentifier))
            {
                return default;
            }

            if (!Identifier.TryParse<UserIdentifier>(reader.GetString(9), out var userIdentifier))
            {
                return default;
            }

            return new OAuthCode(oauthCode, userIdentifier, clientIdentifier, notBefore, notAfter, username, scope, redirect, codeChallenge, codeChallengeMethod, state);
        }

        return default;
    }

    private async Task DeleteExpiredOAuthCodesInternal(DateTime expiration, CancellationToken cancellationToken)
    {
        var query = $"DELETE * FROM {this.options.TableName} WHERE {NotAfterKey} < '@dateTime'";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@dateTime", expiration.ToUniversalTime().ToString(DateTimeFormat));

        await command.ExecuteNonQuery(cancellationToken);
    }
}
