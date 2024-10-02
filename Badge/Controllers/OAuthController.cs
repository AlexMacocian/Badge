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

    [GenerateGet(".well-known/jwks.json")]
    public async Task<IResult> HandleRequest(CancellationToken cancellationToken)
    {
        var keySet = await this.oAuth2Service.GetJsonWebKeySet(cancellationToken);
        return Results.Json(keySet, SerializationContext.Default);
    }

    [GeneratePost("authorize")]
    [RouteFilter<AuthenticatedFilter>]
    public async Task<IResult> Authorize(AuthenticatedUser authenticatedUser, [FromBody] AuthorizeRequest request, CancellationToken cancellationToken)
    {
        var result = await this.oAuth2Service.ValidateOAuth2Request(new OAuthRequest
        {
            Username = authenticatedUser.User.Username,
            ClientId = request.ClientId,
            ClientSecret = request.ClientSecret,
            State = request.State,
            RedirectUri = request.RedirectUri,
            Scopes = request.Scope
        }, cancellationToken);

        return result switch
        {
            OAuthValidationResponse.Success success => Results.Json(new AuthorizeResponse { Code = success.Code, State = success.State }, SerializationContext.Default),
            OAuthValidationResponse.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => throw new InvalidOperationException()
        };
    }
}
