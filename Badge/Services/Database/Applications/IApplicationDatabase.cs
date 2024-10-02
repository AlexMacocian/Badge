using Badge.Models;
using Badge.Models.Identity;

namespace Badge.Services.Database.Applications;

public interface IApplicationDatabase
{
    Task<bool> CreateApplication(Application application, CancellationToken cancellationToken);
    Task<bool> UpdateApplication(Application application, CancellationToken cancellationToken);
    Task<bool> UpdateLogo(string applicationId, string? logo, CancellationToken cancellationToken);
    Task<Application?> GetApplicationById(ApplicationIdentifier id, CancellationToken cancellationToken);
    Task<Application?> GetApplicationByName(string name, CancellationToken cancellationToken);
    Task<bool> UpdateRedirectUris(string applicationId, List<string> redirectUris, CancellationToken cancellationToken);
}
