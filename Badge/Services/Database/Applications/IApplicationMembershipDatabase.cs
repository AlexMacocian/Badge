namespace Badge.Services.Database.Applications;

public interface IApplicationMembershipDatabase
{
    Task<bool> AssignOwner(string applicationId, string ownerId, CancellationToken cancellationToken);
    Task<bool> RemoveOwner(string applicationId, string ownerId, CancellationToken cancellationToken);
    Task<bool> AssignMember(string applicationId, string memberId, CancellationToken cancellationToken);
    Task<bool> RemoveMember(string applicationId, string memberId, CancellationToken cancellationToken);
    Task<IEnumerable<string>> GetOwners(string applicationId, CancellationToken cancellationToken);
    Task<IEnumerable<string>> GetOwnedApplications(string ownerId, CancellationToken cancellationToken);
    Task<IEnumerable<(string ApplicationId, bool Owned)>> GetApplications(string memberId, CancellationToken cancellationToken);
    Task<bool> DeleteApplication(string applicationId, CancellationToken cancellationToken);
    Task<bool> DeleteOwner(string ownerId, CancellationToken cancellationToken);
}
