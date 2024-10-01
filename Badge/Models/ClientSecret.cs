using Badge.Models.Identity;

namespace Badge.Models;

public sealed class ClientSecret(ClientSecretIdentifier id, ApplicationIdentifier applicationIdentifier, DateTime creationDate, DateTime expirationDate, string hash)
{
    public ClientSecretIdentifier Id { get; } = id;
    public ApplicationIdentifier ApplicationIdentifier { get; } = applicationIdentifier;
    public DateTime CreationDate { get; } = creationDate;
    public DateTime ExpirationDate { get; } = expirationDate;
    public string Hash { get; } = hash;
}
