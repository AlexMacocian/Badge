using Badge.Controllers.Models;
using Badge.Extensions;
using Badge.Filters;
using Badge.Models;
using Badge.Services.OAuth2;
using Badge.Services.OAuth2.Models;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using System.Core.Extensions;
using System.Diagnostics.CodeAnalysis;
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
    public IResult GetDiscoveryDocument()
    {
        var discoveryDocument = this.oAuth2Service.GetOAuthDiscoveryDocument();
        return Results.Json(discoveryDocument, SerializationContext.Default);
    }

    [GenerateGet(".well-known/jwks.json")]
    public async Task<IResult> GetJwks(CancellationToken cancellationToken)
    {
        var keySet = await this.oAuth2Service.GetJsonWebKeySet(cancellationToken);
        return Results.Json(keySet, SerializationContext.Default);
    }

    [GenerateGet("userinfo")]
    [RouteFilter<AccessTokenAuthenticatedFilter>]
    public async Task<IResult> GetUserInfo(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var securityToken = httpContext.GetSecurityToken();
        var result = await this.oAuth2Service.GetUserInfo(securityToken, cancellationToken);
        return result switch
        {
            Result<UserInfoResponse>.Success success => Results.Json(success.Result, SerializationContext.Default),
            Result<UserInfoResponse>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => throw new InvalidOperationException("Unexpected user info response received")
        };
    }

    [GeneratePost("token")]
    public async Task<IResult> GetOAuthToken(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var form = await httpContext.Request.ReadFormAsync(cancellationToken);
        var result = await this.oAuth2Service.GetOAuthToken(new OAuthTokenRequest
        {
            ClientId = form["client_id"].FirstOrDefault(),
            GrantType = form["grant_type"].FirstOrDefault(),
            Code = form["code"].FirstOrDefault(),
            CodeVerifier = form["code_verifier"].FirstOrDefault(),
            RedirectUri = form["redirect_uri"].FirstOrDefault(),
            Nonce = form["nonce"].FirstOrDefault(),
            RefreshToken = form["refresh_token"].FirstOrDefault(),
            Scope = form["scope"].FirstOrDefault(),
            ClientSecret = form["client_secret"].FirstOrDefault()
        }, cancellationToken);
        return result switch
        {
            Result<OAuthResponse>.Success success => Results.Json(success.Result, SerializationContext.Default),
            Result<OAuthResponse>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => throw new InvalidOperationException("Unexpected OAuth response received")
        };
    }

    [GenerateGet("scopes")]
    public IResult GetOauthScopes()
    {
        var scopes = this.oAuth2Service.GetOAuthScopes();
        return Results.Json(scopes.Select(s => new OAuthScopeResponse { Description = s.Description, Name = s.Name }), SerializationContext.Default);
    }

    [GeneratePost("authorize")]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> Authorize([FromServices] AuthenticatedUser authenticatedUser, [FromBody] AuthorizeRequest request, CancellationToken cancellationToken)
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
            Nonce = request.Nonce,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod
        }, cancellationToken);

        return result switch
        {
            Result<OAuthResponse>.Success success => Results.Json(success.Result, SerializationContext.Default),
            Result<OAuthResponse>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => throw new InvalidOperationException("Unexpected OAuth response received")
        };
    }
}
