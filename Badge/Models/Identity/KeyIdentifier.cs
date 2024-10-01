namespace Badge.Models.Identity;

public sealed class KeyIdentifier : Identifier
{
    public readonly static IdentifierTypeCode KeyTypeCode = new(4);

    internal KeyIdentifier(Guid uniqueId) : base(KeyTypeCode, uniqueId)
    {
    }
}