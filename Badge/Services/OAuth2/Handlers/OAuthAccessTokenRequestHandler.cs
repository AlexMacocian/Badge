using Badge.Models;
using Badge.Options;
using Badge.Services.JWT;
using Badge.Services.OAuth2.Models;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Extensions;
using System.Extensions.Core;

namespace Badge.Services.OAuth2.Handlers;

public sealed class OAuthAccessTokenRequestHandler : IOAuthRequestHandler
{
    private readonly IJWTService jWTService;
    private readonly OAuthAccessTokenOptions options;
    private readonly ILogger<OAuthAccessTokenRequestHandler> logger;

    public OAuthAccessTokenRequestHandler(
        IJWTService jWTService,
        IOptions<OAuthAccessTokenOptions> options,
        ILogger<OAuthAccessTokenRequestHandler> logger)
    {
        this.jWTService = jWTService.ThrowIfNull();
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<Result<bool>> Handle(OAuthRequest validRequest, OAuthResponseBuilder oAuthResponseBuilder, CancellationToken cancellationToken)
    {
        if (validRequest.ResponseType is not "token")
        {
            return Result.Success(true);
        }

        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            (var token, var tokenType, var expiresIn) = await this.GetAccessToken(validRequest.UserId, validRequest.ClientId, validRequest.Scopes, cancellationToken);
            oAuthResponseBuilder.AddAccessToken(token, expiresIn, tokenType);
            return Result.Success(true);
        }
        catch(Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while handling request");
            return Result.Failure<bool>(errorCode: 500, errorMessage: "Failed to create oauth access token");
        }
    }

    private async Task<(string Token, string TokenType, int ExpiresIn)> GetAccessToken(string? userId, string? clientId, string? scopes, CancellationToken cancellationToken)
    {
        var token = await this.jWTService.GetAccessToken(userId.ThrowIfNull(), clientId.ThrowIfNull(), scopes.ThrowIfNull(), this.options.Duration, cancellationToken);
        if (token is null)
        {
            throw new InvalidOperationException("Failed to create access token");
        }

        var expiresIn = (int)(token.ValidTo.ToUniversalTime() - DateTime.UtcNow).TotalSeconds;
        return (token.Token, "Bearer", expiresIn);
    }
}
