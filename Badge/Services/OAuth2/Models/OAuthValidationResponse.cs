namespace Badge.Services.OAuth2.Models;

public abstract class OAuthValidationResponse
{
    public sealed class Success : OAuthValidationResponse
    {
        public string? Code { get; set; }
        public string? State { get; set; }
    }

    public sealed class Failure : OAuthValidationResponse
    {
        public int ErrorCode { get; set; }
        public string? ErrorMessage { get; set; }
    }
}
