using System.IdentityModel.Tokens.Jwt;

namespace Badge.Extensions;

public static class HttpContextExtensions
{
    private const string JwtKey = "JwtToken";

    public static void SetSecurityToken(this HttpContext context, JwtSecurityToken jwtSecurityToken)
    {
        context.Items.Add(JwtKey, jwtSecurityToken);
    }

    public static JwtSecurityToken? GetSecurityToken(this HttpContext context)
    {
        if (context.Items.TryGetValue(JwtKey, out var securityKey) &&
            securityKey is JwtSecurityToken jwtSecurityToken)
        {
            return jwtSecurityToken;
        }

        return default;
    }
}
