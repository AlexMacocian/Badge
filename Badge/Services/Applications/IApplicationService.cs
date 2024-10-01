using Badge.Services.Applications.Models;

namespace Badge.Services.Applications;

public interface IApplicationService
{
    Task<ApplicationCreationResponse> CreateApplication(string? applicationName, string? ownerId, string? logo, CancellationToken cancellationToken);
    Task<CreateClientSecretResponse> CreateClientSecret(string? applicationId, CancellationToken cancellationToken);
    Task<GetClientSecretsResponse> GetClientSecrets(string? applicationId, CancellationToken cancellationToken);
    Task<DeleteClientSecretResponse> DeleteClientSecret(string? clientSecretId, CancellationToken cancellationToken);
    Task<ApplicationListResponse> GetApplicationsByOwner(string? ownerId, CancellationToken cancellationToken);
    Task<ApplicationWithRightsListResponse> GetApplicationsByMember(string? memberId, CancellationToken cancellationToken);
    Task<AssignMembershipResponse> AddOwner(string? applicationId, string? ownerId, CancellationToken cancellationToken);
    Task<AssignMembershipResponse> AddMember(string? applicationId, string? memberId, CancellationToken cancellationToken);
    Task<RemoveMembershipResponse> RemoveOwner(string? applicationId, string? ownerId, CancellationToken cancellationToken);
    Task<RemoveMembershipResponse> RemoveMember(string? applicationId, string? memberId, CancellationToken cancellationToken);
    Task<UpdateLogoResponse> UpdateLogo(string? applicationId, string? logo, CancellationToken cancellationToken);
}
