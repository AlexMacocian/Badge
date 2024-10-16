using Badge.Extensions;
using Badge.Models;
using Badge.Services.JWT;
using System.Core.Extensions;
using System.Extensions;
using System.IdentityModel.Tokens.Jwt;

namespace Badge.Filters;

public sealed class LoginAuthenticatedFilter(IJWTService jWTService) : IEndpointFilter
{
    private readonly IJWTService jWTService = jWTService.ThrowIfNull();

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (context.HttpContext.GetSecurityToken() is not JwtSecurityToken token)
        {
            return Results.Unauthorized();
        }

        if (token.Claims.None(c => 
            c.Type == JwtExtendedClaimNames.TokenType &&
            c.Value == OAuthTokenTypes.LoginToken &&
            c.Issuer == this.jWTService.GetIssuer()))
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }
}
