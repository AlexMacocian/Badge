namespace Badge.Services.OAuth2.Models;

public sealed class OAuthValidationResponse(string code, string state)
{
    public string Code { get; set; } = code;
    public string State { get; set; } = state;
}
