using Badge.Models;
using Badge.Models.Identity;
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

    public async Task<bool> AssignMember(ApplicationIdentifier applicationId, UserIdentifier memberId, CancellationToken cancellationToken)
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

    public async Task<bool> RemoveMember(ApplicationIdentifier applicationId, UserIdentifier memberId, CancellationToken cancellationToken)
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

    public async Task<bool> AssignOwner(ApplicationIdentifier applicationId, UserIdentifier ownerId, CancellationToken cancellationToken)
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

    public async Task<bool> RemoveOwner(ApplicationIdentifier applicationId, UserIdentifier ownerId, CancellationToken cancellationToken)
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

    public async Task<IEnumerable<UserIdentifier>> GetOwners(ApplicationIdentifier applicationId, CancellationToken cancellationToken)
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

    public async Task<IEnumerable<ApplicationIdentifier>> GetOwnedApplications(UserIdentifier ownerId, CancellationToken cancellationToken)
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

    public async Task<IEnumerable<(ApplicationIdentifier ApplicationId, bool Owned)>> GetApplications(UserIdentifier memberId, CancellationToken cancellationToken)
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

    public async Task<bool> DeleteApplication(ApplicationIdentifier applicationId, CancellationToken cancellationToken)
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

    public async Task<bool> DeleteOwner(UserIdentifier ownerId, CancellationToken cancellationToken)
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

    private async Task<bool> CreateEntry(ApplicationIdentifier applicationId, UserIdentifier member, ApplicationMembership applicationMembership, CancellationToken cancellationToken)
    {
        var entryId = GetEntryId(applicationId, member, applicationMembership);
        var creationDate = DateTime.Now;
        var query = $"INSERT INTO {this.options.TableName}({EntryIdKey}, {ApplicationIdKey}, {MemberIdKey}, {MemberTypeKey}, {CreationDateKey}) Values (@entryId, @applicationId, @member, @type, @creationDate)";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@entryId", entryId);
        command.Parameters.AddWithValue("@applicationId", applicationId.ToString());
        command.Parameters.AddWithValue("@member", member.ToString());
        command.Parameters.AddWithValue("@type", applicationMembership);
        command.Parameters.AddWithValue("@creationDate", creationDate.ToUniversalTime().ToString(DateTimeFormat));

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<bool> RemoveEntry(ApplicationIdentifier applicationId, UserIdentifier ownerId, ApplicationMembership applicationMembership, CancellationToken cancellationToken)
    {
        var entryId = GetEntryId(applicationId, ownerId, applicationMembership);
        var query = $"DELETE FROM {this.options.TableName} WHERE {EntryIdKey} = @entryId";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@entryId", entryId);

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result == 1;
    }

    private async Task<bool> RemoveEntriesByApplication(ApplicationIdentifier applicationId, CancellationToken cancellationToken)
    {
        var query = $"DELETE FROM {this.options.TableName} WHERE {ApplicationIdKey} = '@applicationId'";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@applicationId", applicationId.ToString());

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result >= 0;
    }

    private async Task<bool> RemoveEntriesByOwner(UserIdentifier member, CancellationToken cancellationToken)
    {
        var query = $"DELETE FROM {this.options.TableName} WHERE {MemberIdKey} = @member";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@member", member.ToString());

        var result = await command.ExecuteNonQuery(cancellationToken);
        return result >= 0;
    }

    private async Task<List<ApplicationIdentifier>> GetOwnedApplicationsInternal(UserIdentifier memberId, CancellationToken cancellationToken)
    {
        var query = $"SELECT {ApplicationIdKey} FROM {this.options.TableName} WHERE {MemberIdKey} = @memberId AND {MemberTypeKey} = @memberType";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@memberId", memberId.ToString());
        command.Parameters.AddWithValue("@memberType", ApplicationMembership.Owner);

        var applications = new List<ApplicationIdentifier>();
        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(0);
            if (!Identifier.TryParse<ApplicationIdentifier>(id, out var appId) ||
                appId is null)
            {
                continue;
            }

            applications.Add(appId);
        }

        return applications;
    }

    private async Task<List<(ApplicationIdentifier, bool)>> GetApplicationsInternal(UserIdentifier memberId, CancellationToken cancellationToken)
    {
        var query = $"SELECT * FROM {this.options.TableName} WHERE {MemberIdKey} = @memberId";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@memberId", memberId.ToString());

        var applications = new List<(ApplicationIdentifier, bool)>();
        await foreach(var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(1);
            if (!Identifier.TryParse<ApplicationIdentifier>(id, out var appId) ||
                appId is null)
            {
                continue;
            }

            var type = reader.GetInt32(3);
            applications.Add((appId, (ApplicationMembership)type == ApplicationMembership.Owner));
        }

        return applications;
    }

    private async Task<List<UserIdentifier>> GetOwnersInternal(ApplicationIdentifier applicationId, CancellationToken cancellationToken)
    {
        var query = $"SELECT {MemberIdKey} FROM {this.options.TableName} WHERE {ApplicationIdKey} = @applicationId AND {MemberTypeKey} = @memberType";
        using var command = await this.GetCommand(query, cancellationToken);
        command.Parameters.AddWithValue("@applicationId", applicationId.ToString());
        command.Parameters.AddWithValue("@memberType", ApplicationMembership.Owner);

        var users = new List<UserIdentifier>();
        await foreach (var reader in command.ExecuteReader(cancellationToken))
        {
            var id = reader.GetString(0);
            if (!Identifier.TryParse<UserIdentifier>(id, out var userId) ||
                userId is null)
            {
                continue;
            }

            users.Add(userId);
        }

        return users;
    }

    private static string GetEntryId(ApplicationIdentifier applicationId, UserIdentifier userId, ApplicationMembership applicationMembership)
    {
        return $"{applicationId}-{userId}-{applicationMembership}";
    }
}
