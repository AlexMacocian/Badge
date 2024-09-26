using Badge.Extensions;
using Badge.Filters;
using Badge.Services.JWT;
using Microsoft.IdentityModel.Tokens;
using System.Core.Extensions;
using System.Extensions.Core;
using System.IdentityModel.Tokens.Jwt;

namespace Badge.Middleware;

public sealed class AuthenticationMiddleware : IMiddleware
{
    private const string JWTCookieKey = "jwt_token";

    private readonly IJWTService jWTService;
    private readonly ILogger<AuthenticatedFilter> logger;

    public AuthenticationMiddleware(
        IJWTService jWTService,
        ILogger<AuthenticatedFilter> logger)
    {
        this.jWTService = jWTService.ThrowIfNull();
        this.logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!context.Request.Cookies.TryGetValue(JWTCookieKey, out var value))
        {
            await next(context);
            return;
        }

        var principal = await this.jWTService.ValidateToken(value, context.RequestAborted);
        if (principal is null)
        {
            await next(context);
            return;
        }

        if (principal.Identity is not CaseSensitiveClaimsIdentity identity ||
            identity.SecurityToken is not JwtSecurityToken securityToken)
        {
            await next(context);
            return;
        }

        context.User = principal;
        context.SetSecurityToken(securityToken);
        await next(context);
        return;
    }
}
