using Badge.Extensions;
using Badge.Filters;
using Badge.Services.JWT;
using System.Core.Extensions;

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
        if (!context.Request.Cookies.TryGetValue(JWTCookieKey, out var value))
        {
            if (context.Request.Headers.Authorization.FirstOrDefault() is not string authHeader ||
                !authHeader.StartsWith("Bearer "))
            {
                await next(context);
                return;
            }

            value = authHeader.Replace("Bearer", "").Trim();
        }

        var identity = await this.jWTService.ValidateToken(value, context.RequestAborted);
        if (identity is null)
        {
            await next(context);
            return;
        }

        context.User = identity.ClaimsPrincipal;
        context.SetSecurityToken(identity.JwtSecurityToken);
        await next(context);
        return;
    }
}
