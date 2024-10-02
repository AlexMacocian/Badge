using Badge.Models;
using Badge.Models.Identity;
using Badge.Options;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Data.SQLite;
using System.Extensions.Core;
using System.Text.Json;

namespace Badge.Services.Database.Applications;

public sealed class SQLiteApplicationDatabase : SqliteTableBase<ApplicationDatabaseOptions>, IApplicationDatabase
{
    private const string IdKey = "id";
    private const string NameKey = "name";
    private const string LogoBase64Key = "logo";
    private const string CreationDateKey = "creationdate";
    private const string RedirectUrisKey = "redirecturis";

    private readonly ApplicationDatabaseOptions options;
    private readonly ILogger<SQLiteApplicationDatabase> logger;

    protected override string TableDefinition => $@"
{IdKey} TEXT PRIMARY KEY NOT NULL UNIQUE,
{NameKey} TEXT NOT NULL UNIQUE,
{LogoBase64Key} TEXT NOT NULL,
{CreationDateKey} TEXT NOT NULL,
{RedirectUrisKey} TEXT NOT NULL";

    public SQLiteApplicationDatabase(
        IOptions<ApplicationOptions> options,
        SQLiteConnection sQLiteConnection,
        ILogger<SQLiteApplicationDatabase> logger)
        : base(Microsoft.Extensions.Options.Options.Create(options.ThrowIfNull().Value.ApplicationDatabase!.ThrowIfNull()), sQLiteConnection, logger)
    {
        this.options = options.ThrowIfNull().Value.ApplicationDatabase!.ThrowIfNull();
        this.logger = logger.ThrowIfNull();
    }

    public async Task<bool> CreateApplication(Application application, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.CreateApplicationInternal(application, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while creating application");
            throw;
        }
    }

    public async Task<Application?> GetApplicationById(ApplicationIdentifier id, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.GetApplicationByIdInternal(id, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while fetching application by id");
            throw;
        }
    }

    public async Task<Application?> GetApplicationByName(string name, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.GetApplicationByNameInternal(name, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while fetching application by name");
            throw;
        }
    }

    public async Task<bool> UpdateApplication(Application application, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.UpdateApplicationInternal(application, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while updating application");
            throw;
        }
    }

    public async Task<bool> UpdateLogo(string applicationId, string? logo, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.UpdateLogoInternal(applicationId, logo, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while updating logo");
            throw;
        }
    }

    public async Task<bool> UpdateRedirectUris(string applicationId, List<string> redirectUris, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.UpdateRedirectUrisInternal(applicationId, redirectUris, cancellationToken);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while updating redirect uris");
            throw;
        }
    }

    private async Task<bool> CreateApplicationInternal(Application application, CancellationToken cancellationToken)
    {
        var query = $"INSERT INTO {this.options.TableName}({IdKey}, {NameKey}, {LogoBase64Key}, {CreationDateKey}, {RedirectUrisKey}) Values (@id, @name, @logo, @creation, @redirectUris)";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", application.Id.ToString());
        command.Parameters.AddWithValue("@name", application.Name);
        command.Parameters.AddWithValue("@logo", application.LogoBase64);
        command.Parameters.AddWithValue("@creation", application.CreationDate.ToUniversalTime().ToString(DateTimeFormat));
        command.Parameters.AddWithValue("@redirectUris", JsonSerializer.Serialize(application.RedirectUris, SerializationContext.Default.ListString));

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<Application?> GetApplicationByIdInternal(ApplicationIdentifier id, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {this.options.TableName} WHERE {IdKey} = @id";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", id.ToString());

        await foreach(var reader in command.ExecuteReader(cancellationToken))
        {
            var readId = reader.GetString(0);
            if (!Identifier.TryParse<ApplicationIdentifier>(readId, out var appId) ||
                appId is null)
            {
                continue;
            }

            var name = reader.GetString(1);
            var logo = reader.GetString(2);
            var creationDate = reader.GetDateTime(3);
            var redirectUris = JsonSerializer.Deserialize(reader.GetString(4), SerializationContext.Default.ListString);
            return new Application(appId, name, logo, creationDate, redirectUris ?? []);
        }

        return default;
    }

    private async Task<Application?> GetApplicationByNameInternal(string name, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {this.options.TableName} WHERE {NameKey} = @name";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@name", name);

        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(0);
            if (!Identifier.TryParse<ApplicationIdentifier>(id, out var appId) ||
                appId is null)
            {
                continue;
            }

            var readName = reader.GetString(1);
            var logo = reader.GetString(2);
            var creationDate = reader.GetDateTime(3);
            var redirectUris = JsonSerializer.Deserialize(reader.GetString(4), SerializationContext.Default.ListString);
            return new Application(appId, readName, logo, creationDate, redirectUris ?? []);
        }

        return default;
    }

    private async Task<bool> UpdateApplicationInternal(Application application, CancellationToken cancellationToken)
    {
        var query = $"UPDATE {this.options.TableName} SET {NameKey} = @name, {LogoBase64Key} = @logo, {RedirectUrisKey} = @redirectUris WHERE {IdKey} = @id";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", application.Id);
        command.Parameters.AddWithValue("@name", application.Name);
        command.Parameters.AddWithValue("@logo", application.LogoBase64);
        command.Parameters.AddWithValue("@redirectUris", JsonSerializer.Serialize(application.RedirectUris, SerializationContext.Default.ListString));

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<bool> UpdateLogoInternal(string applicationId, string? logo, CancellationToken cancellationToken)
    {
        var query = $"UPDATE {this.options.TableName} SET {LogoBase64Key} = @logo WHERE {IdKey} = @id";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", applicationId);
        command.Parameters.AddWithValue("@logo", logo ?? string.Empty);

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<bool> UpdateRedirectUrisInternal(string applicationId, List<string> redirectUris, CancellationToken cancellationToken)
    {
        var query = $"UPDATE {this.options.TableName} SET {RedirectUrisKey} = @redirectUris WHERE {IdKey} = @id";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@id", applicationId);
        command.Parameters.AddWithValue("@redirectUris", JsonSerializer.Serialize(redirectUris, SerializationContext.Default.ListString));

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }
}
