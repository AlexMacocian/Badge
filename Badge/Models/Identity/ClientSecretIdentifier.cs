namespace Badge.Models.Identity;

public sealed class ClientSecretIdentifier : Identifier
{
    public readonly static IdentifierTypeCode ClientSecretTypeCode = new(3);

    internal ClientSecretIdentifier(Guid uniqueId) : base(ClientSecretTypeCode, uniqueId)
    {
    }
}