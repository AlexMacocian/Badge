namespace Badge.Models.Identity;

public sealed class ApplicationIdentifier : Identifier
{
    public readonly static IdentifierTypeCode ApplicationTypeCode = new(2);

    internal ApplicationIdentifier(Guid uniqueId) : base(ApplicationTypeCode, uniqueId)
    {
    }
}