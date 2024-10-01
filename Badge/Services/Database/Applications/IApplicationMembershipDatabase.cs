using Badge.Models.Identity;

namespace Badge.Services.Database.Applications;

public interface IApplicationMembershipDatabase
{
    Task<bool> AssignOwner(ApplicationIdentifier applicationId, UserIdentifier ownerId, CancellationToken cancellationToken);
    Task<bool> RemoveOwner(ApplicationIdentifier applicationId, UserIdentifier ownerId, CancellationToken cancellationToken);
    Task<bool> AssignMember(ApplicationIdentifier applicationId, UserIdentifier memberId, CancellationToken cancellationToken);
    Task<bool> RemoveMember(ApplicationIdentifier applicationId, UserIdentifier memberId, CancellationToken cancellationToken);
    Task<IEnumerable<UserIdentifier>> GetOwners(ApplicationIdentifier applicationId, CancellationToken cancellationToken);
    Task<IEnumerable<ApplicationIdentifier>> GetOwnedApplications(UserIdentifier ownerId, CancellationToken cancellationToken);
    Task<IEnumerable<(ApplicationIdentifier ApplicationId, bool Owned)>> GetApplications(UserIdentifier memberId, CancellationToken cancellationToken);
    Task<bool> DeleteApplication(ApplicationIdentifier applicationId, CancellationToken cancellationToken);
    Task<bool> DeleteOwner(UserIdentifier ownerId, CancellationToken cancellationToken);
}
