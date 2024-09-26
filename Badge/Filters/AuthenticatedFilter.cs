using Badge.Extensions;
using System.IdentityModel.Tokens.Jwt;

namespace Badge.Filters;

public sealed class AuthenticatedFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (context.HttpContext.GetSecurityToken() is not JwtSecurityToken jwtSecurityToken)
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }
}
