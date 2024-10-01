namespace Badge.Models.Identity;

public sealed class UserIdentifier : Identifier
{
    public readonly static IdentifierTypeCode UserTypeCode = new(1);

    internal UserIdentifier(Guid uniqueId) : base(UserTypeCode, uniqueId)
    {
    }
}