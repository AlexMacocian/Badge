using Badge.Extensions;
using Badge.Filters;
using Badge.Models;
using Badge.Services.JWT;
using Badge.Services.Users;
using System.Core.Extensions;
using System.Extensions;
using System.Extensions.Core;

namespace Badge.Middleware;

public sealed class AuthenticationMiddleware : IMiddleware
{
    private const string JWTCookieKey = "jwt_token";

    private readonly AuthenticatedUserAccessor authenticatedUserAccessor;
    private readonly IJWTService jWTService;
    private readonly ILogger<LoginAuthenticatedFilter> logger;

    public AuthenticationMiddleware(
        AuthenticatedUserAccessor authenticatedUserAccessor,
        IJWTService jWTService,
        ILogger<LoginAuthenticatedFilter> logger)
    {
        this.authenticatedUserAccessor = authenticatedUserAccessor.ThrowIfNull();
        this.jWTService = jWTService.ThrowIfNull();
        this.logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!context.Request.Cookies.TryGetValue(JWTCookieKey, out var value))
        {
            if (context.Request.Headers.Authorization.FirstOrDefault() is not string authHeader ||
                !authHeader.StartsWith("Bearer "))
            {
                scopedLogger.LogDebug("Failed to authenticate. No authorization found");
                await next(context);
                return;
            }

            value = authHeader.Replace("Bearer", "").Trim();
        }

        var identity = await this.jWTService.ValidateToken(value, context.RequestAborted);
        if (identity is null)
        {
            scopedLogger.LogDebug("Failed to authenticate. Invalid JWT");
            await next(context);
            return;
        }

        var user = await context.RequestServices.GetRequiredService<IUserService>().GetUserById(identity.JwtSecurityToken.Subject, context.RequestAborted);
        if (user is null)
        {
            scopedLogger.LogError("Failed to authenticate. Valid JWT but user not found");
            await next(context);
            return;
        }

        context.User = identity.ClaimsPrincipal;
        context.SetSecurityToken(identity.JwtSecurityToken);
        this.authenticatedUserAccessor.AuthenticatedUser = new AuthenticatedUser(user);
        await next(context);
        return;
    }
}
