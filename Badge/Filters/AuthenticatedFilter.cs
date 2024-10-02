using Badge.Extensions;

namespace Badge.Filters;

public sealed class AuthenticatedFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (context.HttpContext.GetSecurityToken() is null)
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }
}
