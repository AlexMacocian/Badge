using Badge.Services.OAuth2.Models;

namespace Badge.Models;

public sealed class OAuthResponseBuilder
{
    public string Scope { get; }
    public string State { get; }
    public HashSet<string> ResponseTypes { get; } = new();
    public int? ExpiresIn { get; private set; }
    public string? Code { get; private set; }
    public string? AccessToken { get; private set; }
    public string? TokenType { get; private set; }
    public string? OpenIdToken { get; private set; }
    public string? RefreshToken { get; private set; }

    public OAuthResponseBuilder AddCode(string code, int expiresIn)
    {
        this.Code = code;
        this.ExpiresIn = expiresIn;
        this.ResponseTypes.Add("code");
        return this;
    }

    public OAuthResponseBuilder AddAccessToken(string accessToken, int expiresIn, string tokenType)
    {
        this.AccessToken = accessToken;
        this.ExpiresIn = expiresIn;
        this.TokenType = tokenType;
        this.ResponseTypes.Add("token");
        return this;
    }

    public OAuthResponseBuilder AddOpenIdToken(string openIdToken)
    {
        this.OpenIdToken = openIdToken;
        this.ResponseTypes.Add("id_token");
        return this;
    }

    public OAuthResponseBuilder AddRefreshToken(string refreshToken)
    {
        this.RefreshToken = refreshToken;
        return this;
    }

    private OAuthResponseBuilder(string scope, string state)
    {
        this.Scope = scope;
        this.State = state;
    }

    public OAuthResponse Build()
    {
        return new OAuthResponse(this.State, string.Join(' ', this.ResponseTypes), this.Scope, this.ExpiresIn, this.OpenIdToken, this.Code, this.AccessToken, this.TokenType, this.RefreshToken);
    }

    public static OAuthResponseBuilder CreateOAuthResponse(string scope, string state)
    {
        return new OAuthResponseBuilder(scope, state);
    }
}
