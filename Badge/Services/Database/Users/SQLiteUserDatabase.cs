using Badge.Models;
using Badge.Models.Identity;
using Badge.Options;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Data.SQLite;
using System.Extensions.Core;

namespace Badge.Services.Database.Users;

public sealed class SQLiteUserDatabase(IOptions<UserDatabaseOptions> options, SQLiteConnection sQLiteConnection, ILogger<SQLiteUserDatabase> logger)
    : SqliteTableBase<UserDatabaseOptions>(options, sQLiteConnection, logger), IUserDatabase
{
    private const string IdKey = "id";
    private const string UsernameKey = "username";
    private const string PasswordKey = "password";

    private readonly UserDatabaseOptions options = options.ThrowIfNull().Value;
    private readonly ILogger<SQLiteUserDatabase> logger = logger.ThrowIfNull();

    protected override string TableDefinition => $@"
{IdKey} TEXT PRIMARY KEY,
{UsernameKey} TEXT NOT NULL UNIQUE,
{PasswordKey} TEXT NOT NULL";

    public async Task<User?> CreateUser(string username, string password, CancellationToken cancellationToken)
    {
        var scopedLogger = logger.CreateScopedLogger(flowIdentifier: username);
        try
        {
            scopedLogger.LogInformation("Creating user");
            var maybeUser = await CreateUserInternal(username, password, cancellationToken);
            if (maybeUser is null)
            {
                scopedLogger.LogError("Failed to create user");
                return default;
            }

            return maybeUser;
        }
        catch (SQLiteException sqliteEx) when (sqliteEx.Message.Contains("constraint failed"))
        {
            scopedLogger.LogError("User already exists");
            return default;
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while creating user");
            return default;
        }
    }

    public async Task<User?> GetUser(string username, CancellationToken cancellationToken)
    {
        var scopedLogger = logger.CreateScopedLogger(flowIdentifier: username);
        try
        {
            scopedLogger.LogInformation("Fetching user");
            var maybeUser = await GetUserInternal(username, cancellationToken);
            if (maybeUser is null)
            {
                scopedLogger.LogError("User not found");
                return default;
            }

            return maybeUser;
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while fetching user");
            return default;
        }
    }

    private async Task<User?> CreateUserInternal(string username, string password, CancellationToken cancellationToken)
    {
        var id = Identifier.Create<UserIdentifier>();
        var query = $"INSERT INTO {options.TableName} ({IdKey}, {UsernameKey}, {PasswordKey}) VALUES (@id, @username, @password)";
        using var command = await GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", id.ToString());
        command.Parameters.AddWithValue("@username", username);
        command.Parameters.AddWithValue("@password", password);

        var result = await command.ExecuteNonQuery(cancellationToken);
        if (result != 1)
        {
            return default;
        }
        else
        {
            return new User(id, username, password);
        }
    }

    private async Task<User?> GetUserInternal(string username, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {options.TableName} WHERE {UsernameKey} = @username";
        using var command = await GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@username", username);

        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(0);
            if (!Identifier.TryParse<UserIdentifier>(id, out var userId) ||
                userId is null)
            {
                continue;
            }

            return new User(
                id: userId,
                username: reader.GetString(1),
                password: reader.GetString(2));
        }

        return default;
    }
}
