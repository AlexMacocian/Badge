using Badge.Models.Identity;

namespace Badge.Models;

public sealed class Application(ApplicationIdentifier id, string name, string logoBase64, DateTime creationDate, List<string> redirectUris, List<string> scopes)
{
    public ApplicationIdentifier Id { get; } = id;
    public string Name { get; } = name;
    public string LogoBase64 { get; } = logoBase64;
    public List<string> Scopes { get; } = scopes;
    public DateTime CreationDate { get; } = creationDate;
    public List<string> RedirectUris { get; } = redirectUris;
}
