using Badge.Controllers.Models;
using Badge.Filters;
using Badge.Models;
using Badge.Services.Status;
using Badge.Services.Users;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using System.Core.Extensions;

namespace Badge.Controllers;

[GenerateController("/api/users")]
public sealed class UsersController
{
    private readonly IStatusService statusService;
    private readonly IUserService userService;

    public UsersController(
        IStatusService statusService,
        IUserService userService)
    {
        this.statusService = statusService.ThrowIfNull();
        this.userService = userService.ThrowIfNull();
    }

    [GeneratePost("login")]
    public async Task<IResult> Login([FromBody] UsernameWithPassword payload, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await this.userService.Login(payload.Username, payload.Password, cancellationToken);
        if (result is null)
        {
            return Results.Unauthorized();
        }

        var status = await this.statusService.GetStatus();
        httpContext.Response.Cookies.Append("jwt_token", result.Token, new CookieOptions { HttpOnly = true, Secure = status.Environment != "Development", SameSite = SameSiteMode.Strict, Expires = result.ValidTo });
        return Results.Content(result.Token, "text/plain");
    }

    [GeneratePost("create")]
    public async Task<IResult> Create([FromBody] UsernameWithPassword payload, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var result = await this.userService.CreateUser(payload.Username, payload.Password, cancellationToken);
        if (result is null)
        {
            return Results.Unauthorized();
        }

        var status = await this.statusService.GetStatus();
        httpContext.Response.Cookies.Append("jwt_token", result.Token, new CookieOptions { HttpOnly = true, Secure = status.Environment != "Development", SameSite = SameSiteMode.Strict, Expires = result.ValidTo });
        return Results.Content(result.Token, "text/plain");
    }

    [GenerateGet("me")]
    [RouteFilter<LoginAuthenticatedFilter>]
    public Task<IResult> Me(AuthenticatedUser authenticatedUser)
    {
        return authenticatedUser.User switch
        {
            User userModel => Task.FromResult(Results.Json(new UserDetails { Username = userModel.Username }, SerializationContext.Default)),
            _ => Task.FromResult(Results.NotFound("Could not find user"))
        };
    }
}
