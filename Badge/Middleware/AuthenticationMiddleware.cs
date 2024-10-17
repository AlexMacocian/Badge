using Badge.Extensions;
using Badge.Filters;
using Badge.Models;
using Badge.Services.JWT;
using System.Core.Extensions;
using System.Extensions.Core;

namespace Badge.Middleware;

public sealed class AuthenticationMiddleware : IMiddleware
{
    private const string JWTCookieKey = "jwt_token";

    private readonly IJWTService jWTService;
    private readonly ILogger<LoginAuthenticatedFilter> logger;

    public AuthenticationMiddleware(
        IJWTService jWTService,
        ILogger<LoginAuthenticatedFilter> logger)
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

        var identity = await this.jWTService.ValidateToken(value, context.RequestAborted);
        if (identity is null)
        {
            await next(context);
            return;
        }

        if (identity.JwtSecurityToken.GetClaim(JwtExtendedClaimNames.TokenType) is not OAuthTokenTypes.LoginToken)
        {
            scopedLogger.LogInformation("Detected valid token but not of login type. Ignoring");
            await next(context);
            return;
        }

        context.User = identity.ClaimsPrincipal;
        context.SetSecurityToken(identity.JwtSecurityToken);
        await next(context);
        return;
    }
}
