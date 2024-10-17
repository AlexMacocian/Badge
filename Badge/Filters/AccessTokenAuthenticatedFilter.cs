using Badge.Extensions;
using Badge.Models;
using System.IdentityModel.Tokens.Jwt;

namespace Badge.Filters;

public sealed class AccessTokenAuthenticatedFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (context.HttpContext.GetSecurityToken() is not JwtSecurityToken token)
        {
            return Results.Unauthorized();
        }

        if (token.GetClaim(JwtExtendedClaimNames.TokenType) is not OAuthTokenTypes.AccessToken)
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }
}
