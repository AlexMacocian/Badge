﻿using Badge.Controllers.Models;
using Badge.Extensions;
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

    [GenerateGet("token")]
    public async Task<IResult> GetToken(
        [FromForm(Name = "client_id")] string? clientId,
        [FromForm(Name = "grant_type")] string? grantType,
        [FromForm(Name = "code")] string? code,
        [FromForm(Name = "redirect_uri")] string? redirectUri,
        [FromForm(Name = "code_verifier")] string? codeVerifier,
        [FromForm(Name = "nonce")] string? nonce,
        [FromForm(Name = "refresh_token")] string? refresh_token,
        [FromForm(Name = "scope")] string? scope,
        CancellationToken cancellationToken)
    {
        var result = await this.oAuth2Service.GetOAuthToken(new OAuthTokenRequest
        {
            ClientId = clientId,
            GrantType = grantType,
            Code = code,
            CodeVerifier = codeVerifier,
            RedirectUri = redirectUri,
            Nonce = nonce,
            RefreshToken = refresh_token,
            Scope = scope
        }, cancellationToken);
        return result switch
        {
            Result<OAuthResponse>.Success success => Results.Json(success.Result, SerializationContext.Default),
            Result<OAuthResponse>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => throw new InvalidOperationException("Unexpected OAuth response received")
        };
    }

    [GenerateGet("scopes")]
    public Task<IResult> GetOauthScopes()
    {
        var scopes = this.oAuth2Service.GetOAuthScopes();
        return Task.FromResult(Results.Json(scopes.Select(s => new OAuthScopeResponse { Description = s.Description, Name = s.Name }), SerializationContext.Default));
    }

    [GeneratePost("authorize")]
    [RouteFilter<LoginAuthenticatedFilter>]
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
