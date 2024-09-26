using Badge.Extensions;
using Badge.Services.JWT;
using Microsoft.IdentityModel.Tokens;
using System.Core.Extensions;
using System.Extensions.Core;
using System.IdentityModel.Tokens.Jwt;

namespace Badge.Filters;

public sealed class AuthenticatedFilter : IEndpointFilter
{
    private const string JWTCookieKey = "jwt_token";

    private readonly IJWTService jWTService;
    private readonly ILogger<AuthenticatedFilter> logger;

    public AuthenticatedFilter(
        IJWTService jWTService,
        ILogger<AuthenticatedFilter> logger)
    {
        this.jWTService = jWTService.ThrowIfNull();
        this.logger = logger;
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        var httpContext = context.HttpContext;
        if (!httpContext.Request.Cookies.TryGetValue(JWTCookieKey, out var value))
        {
            return Results.Unauthorized();
        }

        var principal = await this.jWTService.ValidateToken(value, httpContext.RequestAborted);
        if (principal is null)
        {
            return Results.Unauthorized();
        }

        if (principal.Identity is not CaseSensitiveClaimsIdentity identity ||
            identity.SecurityToken is not JwtSecurityToken securityToken)
        {
            return Results.Unauthorized();
        }

        httpContext.User = principal;
        httpContext.SetUsername(securityToken.Subject);
        return await next(context);
    }
}
