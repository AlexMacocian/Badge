using Badge.Models;
using Badge.Options;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Data.SQLite;
using System.Extensions;
using System.Extensions.Core;

namespace Badge.Services.Database.Applications;

public sealed class SQLiteApplicationMembershipDatabase : SqliteTableBase<ApplicationMembershipDatabaseOptions>, IApplicationMembershipDatabase
{
    private const string EntryIdKey = "entryid";
    private const string ApplicationIdKey = "applicationid";
    private const string MemberIdKey = "memberid";
    private const string MemberTypeKey = "membertype";
    private const string CreationDateKey = "creationdate";

    private readonly ApplicationMembershipDatabaseOptions options;
    private readonly ILogger<SQLiteApplicationMembershipDatabase> logger;

    protected override string TableDefinition => $@"
{EntryIdKey} TEXT PRIMARY KEY NOT NULL UNIQUE,
{ApplicationIdKey} TEXT NOT NULL,
{MemberIdKey} TEXT NOT NULL,
{MemberTypeKey} INTEGER NOT NULL,
{CreationDateKey} TEXT NOT NULL";

    public SQLiteApplicationMembershipDatabase(
        IOptions<ApplicationMembershipDatabaseOptions> options,
        SQLiteConnection sQLiteConnection,
        ILogger<SQLiteApplicationMembershipDatabase> logger)
        : base(options, sQLiteConnection, logger)
    {
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<bool> AssignMember(string applicationId, string memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.CreateEntry(applicationId, memberId, ApplicationMembership.Member, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
            return false;
        }
    }

    public async Task<bool> RemoveMember(string applicationId, string memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.RemoveEntry(applicationId, memberId, ApplicationMembership.Member, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while removing owner");
            return false;
        }
    }

    public async Task<bool> AssignOwner(string applicationId, string ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.CreateEntry(applicationId, ownerId, ApplicationMembership.Owner, cancellationToken);
        }
        catch(Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
            return false;
        }
    }

    public async Task<bool> RemoveOwner(string applicationId, string ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.RemoveEntry(applicationId, ownerId, ApplicationMembership.Owner, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while removing owner");
            return false;
        }
    }

    public async Task<IEnumerable<string>> GetOwners(string applicationId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.GetOwnersInternal(applicationId, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while retrieving owners");
            throw;
        }
    }

    public async Task<IEnumerable<string>> GetOwnedApplications(string ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.GetOwnedApplicationsInternal(ownerId, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while retrieving owned applications");
            throw;
        }
    }

    public async Task<IEnumerable<(string ApplicationId, bool Owned)>> GetApplications(string memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.GetApplicationsInternal(memberId, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while retrieving applications");
            throw;
        }
    }

    public async Task<bool> DeleteApplication(string applicationId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.RemoveEntriesByApplication(applicationId, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while deleting application");
            throw;
        }
    }

    public async Task<bool> DeleteOwner(string ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.RemoveEntriesByOwner(ownerId, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while deleting owner");
            throw;
        }
    }

    private async Task<bool> CreateEntry(string applicationId, string member, ApplicationMembership applicationMembership, CancellationToken cancellationToken)
    {
        var entryId = GetEntryId(applicationId, member, applicationMembership);
        var creationDate = DateTime.Now;
        var query = $"INSERT INTO {this.options.TableName}({EntryIdKey}, {ApplicationIdKey}, {MemberIdKey}, {MemberTypeKey}, {CreationDateKey}) Values (@entryId, @applicationId, @member, @type, @creationDate)";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@entryId", entryId);
        command.Parameters.AddWithValue("@applicationId", applicationId);
        command.Parameters.AddWithValue("@member", member);
        command.Parameters.AddWithValue("@type", applicationMembership);
        command.Parameters.AddWithValue("@creationDate", creationDate.ToString(DateTimeFormat));

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<bool> RemoveEntry(string applicationId, string ownerId, ApplicationMembership applicationMembership, CancellationToken cancellationToken)
    {
        var entryId = GetEntryId(applicationId, ownerId, applicationMembership);
        var query = $"DELETE FROM {this.options.TableName} WHERE {EntryIdKey} = @entryId";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@entryId", entryId);

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<bool> RemoveEntriesByApplication(string applicationId, CancellationToken cancellationToken)
    {
        var query = $"DELETE FROM {this.options.TableName} WHERE {ApplicationIdKey} = '@applicationId'";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@applicationId", applicationId);

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result >= 0;
    }

    private async Task<bool> RemoveEntriesByOwner(string member, CancellationToken cancellationToken)
    {
        var query = $"DELETE FROM {this.options.TableName} WHERE {MemberIdKey} = @member";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@member", member);

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result >= 0;
    }

    private async Task<List<string>> GetOwnedApplicationsInternal(string memberId, CancellationToken cancellationToken)
    {
        var query = $"SELECT {ApplicationIdKey} FROM {this.options.TableName} WHERE {MemberIdKey} = @memberId AND {MemberTypeKey} = @memberType";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@memberId", memberId);
        command.Parameters.AddWithValue("@memberType", ApplicationMembership.Owner);

        var applications = new List<string>();
        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(0);
            applications.Add(id);
        }

        return applications;
    }

    private async Task<List<(string, bool)>> GetApplicationsInternal(string memberId, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {this.options.TableName} WHERE {MemberIdKey} = @memberId";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@memberId", memberId);

        var applications = new List<(string, bool)>();
        await foreach(var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(1);
            var type = reader.GetInt32(3);
            applications.Add((id, (ApplicationMembership)type == ApplicationMembership.Owner));
        }

        return applications;
    }

    private async Task<List<string>> GetOwnersInternal(string applicationId, CancellationToken cancellationToken)
    {
        var query = $"SELECT {MemberIdKey} FROM {this.options.TableName} WHERE {ApplicationIdKey} = @applicationId AND {MemberTypeKey} = @memberType";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@applicationId", applicationId);
        command.Parameters.AddWithValue("@memberType", ApplicationMembership.Owner);

        var applications = new List<string>();
        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(0);
            applications.Add(id);
        }

        return applications;
    }

    private static string GetEntryId(string applicationId, string ownerId, ApplicationMembership applicationMembership)
    {
        return $"{applicationId}-{ownerId}-{applicationMembership}";
    }
}
