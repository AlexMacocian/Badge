using Badge.Models;
using Badge.Models.Identity;
using Badge.Options;
using Badge.Services.Database.OAuth;
using Badge.Services.OAuth2.Models;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Extensions;
using System.Extensions.Core;

namespace Badge.Services.OAuth2.Handlers;

public sealed class OAuthCodeRequestHandler : IOAuthRequestHandler
{
    private readonly IOAuthCodeDatabase oAuthCodeDatabase;
    private readonly OAuthCodeOptions options;
    private readonly ILogger<OAuthCodeRequestHandler> logger;

    public OAuthCodeRequestHandler(
        IOAuthCodeDatabase oAuthCodeDatabase,
        IOptions<OAuthCodeOptions> options,
        ILogger<OAuthCodeRequestHandler> logger)
    {
        this.oAuthCodeDatabase = oAuthCodeDatabase.ThrowIfNull();
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<Result<bool>> Handle(OAuthRequest validRequest, OAuthResponseBuilder oAuthResponseBuilder, CancellationToken cancellationToken)
    {
        if (validRequest.ResponseType?.Split(' ').Any(r => r == "code") is not true)
        {
            return Result.Success(true);
        }
        
        // UserId should be validated already
        if (!Identifier.TryParse<UserIdentifier>(validRequest.UserId, out var userIdentifier))
        {
            return Result.Success(true);
        }

        // ClientId should be validated already
        if (!Identifier.TryParse<ApplicationIdentifier>(validRequest.ClientId, out var clientIdentifier))
        {
            return Result.Success(true);
        }

        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            (var expiresIn, var code) = await GetOAuthCode(userIdentifier, clientIdentifier, validRequest.Username, validRequest.Scopes, validRequest.RedirectUri, validRequest.CodeChallenge, validRequest.CodeChallengeMethod, validRequest.State, cancellationToken);
            oAuthResponseBuilder.AddCode(code, expiresIn);
            return Result.Success(true);
        }
        catch(Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while handling request");
            return Result.Failure<bool>(500, "Failed to create oauth code");
        }
    }

    private async Task<(int ExpiresIn, string Code)> GetOAuthCode(
        UserIdentifier userIdentifier,
        ApplicationIdentifier clientIdentifier,
        string? username,
        string? scopes,
        string? redirectUri,
        string? codeChallenge,
        string? codeChallengeMethod,
        string? state,
        CancellationToken cancellationToken)
    {
        Enum.TryParse<CodeChallengeMethods>(codeChallengeMethod ?? string.Empty, true, out var parsedChallengeMethod);
        var code = Guid.NewGuid().ToString().Replace("-", "");
        var notBefore = DateTime.Now;
        var notAfter = notBefore + this.options.Duration;
        var oauthCode = new OAuthCode(code, userIdentifier, clientIdentifier, notBefore, notAfter, username.ThrowIfNull(), scopes.ThrowIfNull(), redirectUri.ThrowIfNull(), codeChallenge, parsedChallengeMethod, state.ThrowIfNull());
        if (!await this.oAuthCodeDatabase.CreateOAuthCode(oauthCode, cancellationToken))
        {
            throw new InvalidOperationException("Failed to create oauth code");
        }

        var expiresIn = (int)(notAfter.ToUniversalTime() - DateTime.UtcNow).TotalSeconds;
        return (expiresIn, code);
    }
}
