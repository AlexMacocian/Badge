using Badge.Models;
using Badge.Options;
using Badge.Services.JWT;
using Badge.Services.OAuth2.Models;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Extensions.Core;

namespace Badge.Services.OAuth2.Handlers;

public sealed class OAuthOpenIdTokenRequestHandler : IOAuthRequestHandler
{
    private readonly IJWTService jWTService;
    private readonly OAuthOpenIdTokenOptions options;
    private readonly ILogger<OAuthOpenIdTokenRequestHandler> logger;

    public OAuthOpenIdTokenRequestHandler(
        IJWTService jWTService,
        IOptions<OAuthOpenIdTokenOptions> options,
        ILogger<OAuthOpenIdTokenRequestHandler> logger)
    {
        this.jWTService = jWTService.ThrowIfNull();
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
            var openIdToken = await this.jWTService.GetOpenIDToken(
                        validRequest.UserId.ThrowIfNull(),
                        validRequest.ClientId.ThrowIfNull(),
                        validRequest.Scopes,
                        validRequest.Nonce.ThrowIfNull(),
                        oAuthResponseBuilder.AccessToken,
                        this.options.Duration,
                        cancellationToken);
            if (openIdToken is null)
            {
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
