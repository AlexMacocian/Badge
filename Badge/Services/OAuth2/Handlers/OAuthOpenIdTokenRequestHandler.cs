﻿using Badge.Models;
using Badge.Options;
using Badge.Services.JWT;
using Badge.Services.OAuth2.Models;
using Badge.Services.Users;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Extensions.Core;

namespace Badge.Services.OAuth2.Handlers;

public sealed class OAuthOpenIdTokenRequestHandler : IOAuthRequestHandler
{
    private readonly IJWTService jWTService;
    private readonly IUserService userService;
    private readonly OAuthOpenIdTokenOptions options;
    private readonly ILogger<OAuthOpenIdTokenRequestHandler> logger;

    public OAuthOpenIdTokenRequestHandler(
        IJWTService jWTService,
        IUserService userService,
        IOptions<OAuthOpenIdTokenOptions> options,
        ILogger<OAuthOpenIdTokenRequestHandler> logger)
    {
        this.jWTService = jWTService.ThrowIfNull();
        this.userService = userService.ThrowIfNull();
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<Result<bool>> Handle(OAuthRequest validRequest, OAuthResponseBuilder oAuthResponseBuilder, CancellationToken cancellationToken)
    {
        if (validRequest.Scopes?.Split(' ').Contains("openid") is not true ||
            oAuthResponseBuilder.AccessToken is null)
        {
            return Result.Success(true);
        }

        if (validRequest.Nonce is null)
        {
            return Result.Failure<bool>(errorCode: 400, errorMessage: "Missing nonce");
        }

        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            var user = await this.userService.GetUserById(validRequest.UserId, cancellationToken);
            if (user is null)
            {
                scopedLogger.LogError($"Failed to find user by id {validRequest.UserId}");
                return Result.Failure<bool>(errorCode: 500, errorMessage: "Failed to create openid token");
            }

            var openIdToken = await this.jWTService.GetOpenIDToken(
                        validRequest.UserId.ThrowIfNull(),
                        validRequest.ClientId.ThrowIfNull(),
                        user.Username,
                        validRequest.Scopes,
                        validRequest.Nonce.ThrowIfNull(),
                        oAuthResponseBuilder.AccessToken,
                        this.options.Duration,
                        cancellationToken);
            if (openIdToken is null)
            {
                scopedLogger.LogError($"Failed to create openid token");
                return Result.Failure<bool>(errorCode: 500, errorMessage: "Failed to create openid token");
            }

            oAuthResponseBuilder.AddOpenIdToken(openIdToken.Token);
            return Result.Success(true);
        }
        catch(Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while handling request");
            return Result.Failure<bool>(errorCode: 500, errorMessage: "Failed to create openid token");
        }
    }
}
