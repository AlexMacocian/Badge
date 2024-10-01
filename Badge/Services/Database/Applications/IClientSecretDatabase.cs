﻿using Badge.Models;
using Badge.Models.Identity;

namespace Badge.Services.Database.Applications;

public interface IClientSecretDatabase
{
    Task<IEnumerable<ClientSecret>> GetClientSecrets(ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken);
    Task<bool> StoreClientSecret(ClientSecret clientSecret, CancellationToken cancellationToken);
    Task<ClientSecret?> GetClientSecret(ClientSecretIdentifier clientSecretIdentifier, CancellationToken cancellationToken);
    Task<bool> RemoveClientSecret(ClientSecretIdentifier clientSecretIdentifier, CancellationToken cancellationToken);
    Task<bool> RemoveApplication(ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken);
}
