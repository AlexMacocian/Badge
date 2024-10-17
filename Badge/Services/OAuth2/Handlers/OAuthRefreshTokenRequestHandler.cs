using Badge.Models;
using Badge.Options;
using Badge.Services.Applications;
using Badge.Services.Database.Applications;
using Badge.Services.Database.OAuth;
using Badge.Services.JWT;
using Badge.Services.OAuth2.Models;
using Badge.Services.Passwords;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Extensions;
using System.Extensions.Core;

namespace Badge.Services.OAuth2.Handlers;

public sealed class OAuthRefreshTokenRequestHandler : IOAuthRequestHandler
{
    private readonly IJWTService jWTService;
    private readonly IOAuthRefreshTokenDatabase database;
    private readonly OAuthRefreshTokenOptions options;
    private readonly ILogger<OAuthRefreshTokenRequestHandler> logger;

    public OAuthRefreshTokenRequestHandler(
        IJWTService jWTService,
        IOAuthRefreshTokenDatabase database,
        IOptions<OAuthRefreshTokenOptions> options,
        ILogger<OAuthRefreshTokenRequestHandler> logger)
    {
        this.jWTService = jWTService.ThrowIfNull();
        this.database = database.ThrowIfNull();
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<Result<bool>> Handle(OAuthRequest validRequest, OAuthResponseBuilder oAuthResponseBuilder, CancellationToken cancellationToken)
    {
        if (validRequest.ResponseType != "token")
        {
            return Result.Success(true);
        }

        if (validRequest.Scopes?.Split(' ').Contains("offline_access") is not true)
        {
            return Result.Success(true);
        }

        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            //TODO: Not exactly correct as this handler should also validate the client secret, but since it's executed after the Access Token handler, we know that the client secret is validated
            var refreshToken = await this.jWTService.GetRefreshToken(
                validRequest.UserId.ThrowIfNull(),
                validRequest.ClientId.ThrowIfNull(),
                validRequest.Scopes,
                validRequest.RedirectUri.ThrowIfNull(),
                validRequest.ClientSecret.ThrowIfNull(),
                this.options.Duration,
                cancellationToken);
            if (refreshToken is null)
            {
                return Result.Failure<bool>(errorCode: 500, errorMessage: "Failed to create refresh token");
            }

            var result = await this.database.CreateRefreshToken(refreshToken.Token, refreshToken.ValidTo, cancellationToken);
            if (result is false)
            {
                return Result.Failure<bool>(errorCode: 500, errorMessage: "Failed to create refresh token");
            }

            oAuthResponseBuilder.AddRefreshToken(refreshToken.Token);
            return Result.Success(true);
        }
        catch(Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while handling request");
            return Result.Failure<bool>(errorCode: 500, errorMessage: "Failed to create refresh token");
        }
    }
}
