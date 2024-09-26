namespace Badge.Services.OAuth2.Models;

public sealed class OAuthRequest
{
    public string? Username { get; set; }
    public string? ClientSecret { get; set; }
    public string? ClientId { get; set; }
    public string? Scopes { get; set; }
    public string? RedirectUri { get; set; }
    public string? State { get; set;}
}
