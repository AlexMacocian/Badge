using Badge.Models;

namespace Badge.Services.Database.Applications;

public interface IApplicationDatabase
{
    Task<bool> CreateApplication(Application application, CancellationToken cancellationToken);
    Task<bool> UpdateApplication(Application application, CancellationToken cancellationToken);
    Task<bool> UpdateLogo(string applicationId, string? logo, CancellationToken cancellationToken);
    Task<Application?> GetApplicationById(string id, CancellationToken cancellationToken);
    Task<Application?> GetApplicationByName(string name, CancellationToken cancellationToken);
}
