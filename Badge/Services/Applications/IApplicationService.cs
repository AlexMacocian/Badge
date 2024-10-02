using Badge.Models;
using Badge.Services.Applications.Models;

namespace Badge.Services.Applications;

public interface IApplicationService
{
    Task<Result<Application>> CreateApplication(string? applicationName, string? ownerId, string? logo, CancellationToken cancellationToken);
    Task<Result<CreateClientSecretResponse>> CreateClientSecret(string? applicationId, CancellationToken cancellationToken);
    Task<Result<List<ClientSecret>>> GetClientSecrets(string? applicationId, CancellationToken cancellationToken);
    Task<Result<bool>> DeleteClientSecret(string? clientSecretId, string? ownerApplicationId, CancellationToken cancellationToken);
    Task<Result<List<Application>>> GetApplicationsByOwner(string? ownerId, CancellationToken cancellationToken);
    Task<Result<List<ApplicationWithRights>>> GetApplicationsByMember(string? memberId, CancellationToken cancellationToken);
    Task<Result<bool>> AddOwner(string? applicationId, string? ownerId, CancellationToken cancellationToken);
    Task<Result<bool>> AddMember(string? applicationId, string? memberId, CancellationToken cancellationToken);
    Task<Result<bool>> RemoveOwner(string? applicationId, string? ownerId, CancellationToken cancellationToken);
    Task<Result<bool>> RemoveMember(string? applicationId, string? memberId, CancellationToken cancellationToken);
    Task<Result<bool>> UpdateLogo(string? applicationId, string? logo, CancellationToken cancellationToken);
    Task<Result<bool>> UpdateRedirectUris(string? applicationId, List<string>? redirectUris, CancellationToken cancellationToken);
}
