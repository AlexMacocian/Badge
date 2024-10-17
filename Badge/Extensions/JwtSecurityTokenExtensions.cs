using System.IdentityModel.Tokens.Jwt;

namespace Badge.Extensions;

public static class JwtSecurityTokenExtensions
{
    public static string? GetClaim(this JwtSecurityToken token, string claimName)
    {
        return token.Claims.FirstOrDefault(c => c.Type == claimName)?.Value;
    }
}
