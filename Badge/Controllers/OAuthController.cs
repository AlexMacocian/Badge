using Badge.Controllers.Models;
using Badge.Filters;
using Badge.Models;
using Badge.Services.OAuth2;
using Badge.Services.OAuth2.Models;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using System.Core.Extensions;
using System.Extensions;

namespace Badge.Controllers;

[GenerateController("api/oauth")]
public sealed class OAuthController
{
    private readonly IOAuth2Service oAuth2Service;
    private readonly ILogger<OAuthController> logger;

    public OAuthController(
        IOAuth2Service oAuth2Service,
        ILogger<OAuthController> logger)
    {
        this.oAuth2Service = oAuth2Service.ThrowIfNull();
        this.logger = logger.ThrowIfNull();
    }

    [GenerateGet(".well-known/openid-configuration")]
    public async Task<IResult> GetDiscoveryDocument(CancellationToken cancellationToken)
    {
        var discoveryDocument = await this.oAuth2Service.GetOAuthDiscoveryDocument(cancellationToken);
        return Results.Json(discoveryDocument, SerializationContext.Default);
    }

    [GenerateGet(".well-known/jwks.json")]
    public async Task<IResult> GetJwks(CancellationToken cancellationToken)
    {
        var keySet = await this.oAuth2Service.GetJsonWebKeySet(cancellationToken);
        return Results.Json(keySet, SerializationContext.Default);
    }

    [GenerateGet("scopes")]
    public Task<IResult> GetOauthScopes()
    {
        var scopes = this.oAuth2Service.GetOAuthScopes();
        return Task.FromResult(Results.Json(scopes.Select(s => new OAuthScopeResponse { Description = s.Description, Name = s.Name }), SerializationContext.Default));
    }

    [GeneratePost("authorize")]
    [RouteFilter<AuthenticatedFilter>]
    public async Task<IResult> Authorize(AuthenticatedUser authenticatedUser, [FromBody] AuthorizeRequest request, CancellationToken cancellationToken)
    {
        var result = await this.oAuth2Service.GetAuthorization(new OAuthRequest
        {
            Username = authenticatedUser.User.Username,
            UserId = authenticatedUser.User.Id.ToString(),
            ClientId = request.ClientId,
            ClientSecret = request.ClientSecret,
            State = request.State,
            RedirectUri = request.RedirectUri,
            Scopes = request.Scope,
            ResponseType = request.ResponseType,
            Nonce = request.Nonce
        }, cancellationToken);

        return result switch
        {
            Result<OAuthResponse>.Success success => Results.Json(success.Result.As<Dictionary<string, string>>(), SerializationContext.Default),
            Result<OAuthResponse>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => throw new InvalidOperationException()
        };
    }
}
