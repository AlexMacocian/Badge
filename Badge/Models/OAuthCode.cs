namespace Badge.Models;

public sealed class OAuthCode(string code, DateTime notBefore, DateTime notAfter)
{
    public string Code { get; } = code;
    public DateTime NotBefore { get; } = notBefore;
    public DateTime NotAfter { get; } = notAfter;
}
