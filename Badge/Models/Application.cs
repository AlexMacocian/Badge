using Badge.Models.Identity;

namespace Badge.Models;

public sealed class Application(ApplicationIdentifier id, string name, string logoBase64, DateTime creationDate)
{
    public ApplicationIdentifier Id { get; } = id;
    public string Name { get; } = name;
    public string LogoBase64 { get; } = logoBase64;
    public DateTime CreationDate { get; } = creationDate;
}
