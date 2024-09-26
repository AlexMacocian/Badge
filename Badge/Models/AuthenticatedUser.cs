using Badge.Extensions;
using Badge.Services.Users;
using System.IdentityModel.Tokens.Jwt;

namespace Badge.Models;

public sealed class AuthenticatedUser(User user)
{
    public User User { get; } = user;

    public static async ValueTask<AuthenticatedUser?> BindAsync(HttpContext context)
    {
        if (context.GetSecurityToken() is not JwtSecurityToken securityToken)
        {
            return default;
        }

        var user = await context.RequestServices.GetRequiredService<IUserService>().GetUserByUsername(securityToken.Subject, context.RequestAborted);
        if (user is null)
        {
            return default;
        }

        return new AuthenticatedUser(user);
    }
}
