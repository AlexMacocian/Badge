namespace Badge.Models;

public sealed class JwtToken(string token, DateTime validTo)
{
    public string Token { get; set; } = token;
    public DateTime ValidTo { get; set; } = validTo;
}
