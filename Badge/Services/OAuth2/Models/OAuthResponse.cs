namespace Badge.Services.OAuth2.Models;

public abstract class OAuthResponse : Dictionary<string, string>
{
    public string State => this["state"];
    public string ResponseType => this["responseType"];
    public string IdToken
    {
        get => this["idToken"];
        set
        {
            if (!this.ResponseType.StartsWith("id_token"))
            {
                this["responseType"] = $"id_token {this.ResponseType}";
            }

            this["idToken"] = value;
        }
    }

    public OAuthResponse(string state, string responseType)
    {
        this["state"] = state;
        this["responseType"] = responseType;
    }

    public sealed class OAuthCodeResponse : OAuthResponse
    {
        public string Code => this["code"];

        public OAuthCodeResponse(string code, string state) : base(state, "code")
        {
            this["code"] = code;
        }
    }

    public sealed class OAuthTokenResponse : OAuthResponse
    {
        public string Token => this["token"];
        public string ExpiresIn => this["expiresIn"];
        public string TokenType => this["tokenType"];

        public OAuthTokenResponse(string token, DateTime expirationDate, string state) : base(state, "token")
        {
            this["token"] = token;
            this["expiresIn"] = ((int)(expirationDate.ToUniversalTime() - DateTime.UtcNow).TotalSeconds).ToString();
            this["tokenType"] = "Bearer";
        }
    }
}
