namespace Badge.Services.OAuth2.Models;

public sealed class OAuthTokenRequest
{
    public string? ClientId { get; set; }
    public string? GrantType { get; set; }
    public string? Code { get; set; }
    public string? RedirectUri { get; set; }
    public string? CodeVerifier { get; set; }
    public string? Nonce { get; set; }
    public string? RefreshToken { get; set; }
    public string? Scope { get; set; }
}
