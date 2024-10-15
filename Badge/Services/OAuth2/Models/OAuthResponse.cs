namespace Badge.Services.OAuth2.Models;

public abstract class OAuthResponse : Dictionary<string, string>
{
    public string State => this["state"];
    public string OpenId
    {
        get => this["openid"];
        set => this["openid"] = value;
    }

    public OAuthResponse(string state)
    {
        this["state"] = state;
    }

    public sealed class OAuthCodeResponse : OAuthResponse
    {
        public string Code => this["code"];

        public OAuthCodeResponse(string code, string state) : base(state)
        {
            this["code"] = code;
        }
    }

    public sealed class OAuthTokenResponse : OAuthResponse
    {
        public string Token => this["token"];

        public OAuthTokenResponse(string token, string state) : base(state)
        {
            this["token"] = token;
        }
    }
}
