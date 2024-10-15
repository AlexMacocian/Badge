namespace Badge.Models;

public sealed class OAuthCode(string code, DateTime notBefore, DateTime notAfter, string username, string scope, string redirect)
{
    public string Code { get; } = code;
    public DateTime NotBefore { get; } = notBefore;
    public DateTime NotAfter { get; } = notAfter;
    public string Username { get; } = username;
    public string Scope { get; } = scope;
    public string Redirect { get; } = redirect;
}
