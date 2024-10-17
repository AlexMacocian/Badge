using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Badge.Models;

public sealed class ValidatedIdentity(JwtSecurityToken jwtSecurityToken, ClaimsPrincipal claimsPrincipal)
{
    public JwtSecurityToken JwtSecurityToken { get; } = jwtSecurityToken;
    public ClaimsPrincipal ClaimsPrincipal { get; } = claimsPrincipal;
}
