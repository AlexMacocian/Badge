using Badge.Extensions;
using Badge.Models;
using Badge.Models.Identity;
using Badge.Models.JsonWebKeys;
using Badge.Options;
using Badge.Services.Certificates;
using Badge.Services.Database.Applications;
using Badge.Services.Database.OAuth;
using Badge.Services.JWT;
using Badge.Services.OAuth2.Handlers;
using Badge.Services.OAuth2.Models;
using Badge.Services.Users;
using Microsoft.Extensions.Options;
using System.Cache;
using System.Core.Extensions;
using System.Extensions;
using System.Extensions.Core;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Convert = System.Convert;

namespace Badge.Services.OAuth2;

public sealed class OAuth2Service : IOAuth2Service
{
    private static AsyncValueCache<JsonWebKeySetResponse>? JsonWebKeySets;

    private readonly IEnumerable<IOAuthRequestHandler> requestHandlers;
    private readonly IUserService userService;
    private readonly IJWTService jWTService;
    private readonly IApplicationDatabase applicationDatabase;
    private readonly IOAuthCodeDatabase oAuthCodeDatabase;
    private readonly ICertificateService certificateService;
    private readonly OAuthServiceOptions options;
    private readonly ILogger<OAuth2Service> logger;

    public OAuth2Service(
        IEnumerable<IOAuthRequestHandler> requestHandlers,
        IUserService userService,
        IJWTService jWTService,
        IApplicationDatabase applicationDatabase,
        IOAuthCodeDatabase oAuthCodeDatabase,
        ICertificateService certificateService,
        IOptions<OAuthServiceOptions> options,
        ILogger<OAuth2Service> logger)
    {
        this.requestHandlers = requestHandlers.ThrowIfNull();
        this.userService = userService.ThrowIfNull();
        this.jWTService = jWTService.ThrowIfNull();
        this.applicationDatabase = applicationDatabase.ThrowIfNull();
        this.oAuthCodeDatabase = oAuthCodeDatabase.ThrowIfNull();
        this.certificateService = certificateService.ThrowIfNull();
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();

        //TODO: Not exactly correct, as there's up to 5 minutes that a new signing key will not be reflected in this cache
        JsonWebKeySets ??= new AsyncValueCache<JsonWebKeySetResponse>(this.GetJsonWebKeySetInternal, this.options.KeySetCacheDuration);
    }

    public async Task<Result<UserInfoResponse>> GetUserInfo(JwtSecurityToken? requestAccessToken, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (requestAccessToken is null)
        {
            scopedLogger.LogDebug("Security token is null");
            return Result.Failure<UserInfoResponse>(errorCode: 401, errorMessage: "Missing access token");
        }

        if (requestAccessToken.Subject is not string userId)
        {
            scopedLogger.LogError("Could not retrieve user info. No user id in subject field");
            return Result.Failure<UserInfoResponse>(errorCode: 400, errorMessage: "Invalid access token");
        }

        var user = await this.userService.GetUserById(userId, cancellationToken);
        if (user is null)
        {
            scopedLogger.LogError("Could not find user by id");
            return Result.Failure<UserInfoResponse>(errorCode: 500, errorMessage: "Could not resolve user info");
        }

        return Result.Success(new UserInfoResponse
        {
            UserId = user.Id.ToString(),
            Username = user.Username
        });
    }

    public async Task<JsonWebKeySetResponse> GetJsonWebKeySet(CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            if (JsonWebKeySets is null)
            {
                throw new InvalidOperationException("KeySet cache cannot be null");
            }

            return await JsonWebKeySets.GetValue();
        }
        catch(Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while fetching json web keyset");
            throw;
        }
    }

    public async Task<Result<OAuthResponse>> GetAuthorization(OAuthRequest oAuthRequest, CancellationToken cancellationToken)
    {
        var validation = await this.ValidateRequest(oAuthRequest, cancellationToken);
        if (validation is Result<bool>.Failure validationFailure)
        {
            return Result.Failure<OAuthResponse>(errorCode: validationFailure.ErrorCode, errorMessage: validationFailure.ErrorMessage);
        }

        return await this.HandleRequest(oAuthRequest, cancellationToken);
    }

    public Task<Result<OAuthResponse>> GetOAuthToken(OAuthTokenRequest request, CancellationToken cancellationToken)
    {
        return request.GrantType switch
        {
            "authorization_code" => this.GetOAuthTokenFromCodeInternal(request, cancellationToken),
            "refresh_token" => this.GetOAuthTokenFromRefreshTokenInternal(request, cancellationToken),
            _ => Task.FromResult(Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: request.GrantType is null ? "Missing grant type" : $"Unsupported grant type {request.GrantType}"))
        };
    }

    public OAuthDiscoveryDocument GetOAuthDiscoveryDocument()
    {
        return new OAuthDiscoveryDocument(
            issuer: this.options.Issuer ?? throw new InvalidOperationException("Issuer is null"),
            authorizationEndpoint: $"{this.options.Issuer}/oauth/authorize",
            tokenEndpoint: $"{this.options.Issuer}/api/oauth/token",
            userInfoEndpoint: $"{this.options.Issuer}/api/oauth/userinfo",
            jwksUri: $"{this.options.Issuer}/api/oauth/.well-known/jwks.json",
            responseTypesSupported: ["code", "token"],
            subjectTypesSupported: ["public"],
            idTokenSigningAlgValuesSupported: [this.jWTService.GetSigningAlg()],
            scopesSupported: this.options.ScopesSupported?.Select(s => s.Name).OfType<string>().ToList() ?? [],
            tokenEndpointAuthMethodsSupported: ["client_secret_post"],
            grantTypesSupported: this.options.GrantTypesSupported ?? [],
            claimsSupported: ["sub"]);
    }

    public IEnumerable<OAuthScope> GetOAuthScopes()
    {
        return this.options.ScopesSupported?.ToList() ?? Enumerable.Empty<OAuthScope>();
    }

    private async Task<Result<OAuthResponse>> GetOAuthTokenFromRefreshTokenInternal(OAuthTokenRequest request, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        var validation = this.ValidateTokenRequest(request);
        if (validation is Result<bool>.Failure failure)
        {
            scopedLogger.LogDebug($"Validation failed. Error message: {failure.ErrorMessage}");
            return Result.Failure<OAuthResponse>(errorCode: failure.ErrorCode, errorMessage: failure.ErrorMessage);
        }

        if (request.RefreshToken is null)
        {
            scopedLogger.LogDebug("Missing refresh token");
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Missing refresh token");
        }

        var validIdentity = await this.jWTService.ValidateToken(request.RefreshToken, cancellationToken);
        if (validIdentity is null)
        {
            scopedLogger.LogDebug("Invalid refresh token");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        var refreshToken = validIdentity.JwtSecurityToken;
        if (refreshToken.Subject is null ||
            !Identifier.TryParse<UserIdentifier>(refreshToken.Subject, out var userIdentifier))
        {
            scopedLogger.LogError($"Refresh token is valid but could not parse user id {refreshToken.Subject}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        if (refreshToken.Audiences.FirstOrDefault() is null ||
            !Identifier.TryParse<ApplicationIdentifier>(refreshToken.Audiences.FirstOrDefault(), out var applicationIdentifier))
        {
            scopedLogger.LogError($"Refresh token is valid but could not parse client id {refreshToken.Audiences.FirstOrDefault()}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        if (refreshToken.GetClaim(JwtExtendedClaimNames.AccessScope) is not string accessScope)
        {
            scopedLogger.LogError($"Refresh token is valid but could not find claim {JwtExtendedClaimNames.AccessScope}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        if (refreshToken.GetClaim(JwtExtendedClaimNames.Scope) is not string refreshTokenScope)
        {
            scopedLogger.LogError($"Refresh token is valid but could not find claim {JwtExtendedClaimNames.Scope}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        if (refreshToken.GetClaim(JwtExtendedClaimNames.TokenType) is not string refreshTokenType)
        {
            scopedLogger.LogError($"Refresh token is valid but could not find claim {JwtExtendedClaimNames.TokenType}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        if (refreshToken.GetClaim(JwtExtendedClaimNames.RedirectUri) is not string redirectUri)
        {
            scopedLogger.LogError($"Refresh token is valid but could not find claim {JwtExtendedClaimNames.RedirectUri}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        if (refreshToken.GetClaim(JwtExtendedClaimNames.ClientSecret) is not string clientSecret)
        {
            scopedLogger.LogError($"Refresh token is valid but could not find claim {JwtExtendedClaimNames.ClientSecret}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        if (refreshTokenType is not OAuthTokenTypes.RefreshToken)
        {
            scopedLogger.LogError($"Refresh token is valid but not of type {OAuthTokenTypes.RefreshToken}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        var application = await this.applicationDatabase.GetApplicationById(applicationIdentifier, cancellationToken);
        if (application is null)
        {
            scopedLogger.LogError($"Could not find application {applicationIdentifier}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        // Check that all scopes (including offline_access) are enabled on the application
        if (!accessScope.Split(' ').Append(refreshTokenScope).All(application.Scopes.Contains))
        {
            scopedLogger.LogDebug($"Unsupported scopes. Request scopes: {accessScope} {refreshTokenScope}. Application supports: {string.Join(' ', application.Scopes)}");
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "One or more access scopes are no longer supported by the application");
        }

        // Check the optional scope parameter. If it's provided, check that it's not requesting more than the original. Requesting less is allowed
        if (request.Scope is not null &&
            request.Scope.Split(' ').Any(s => !accessScope.Split(' ').Contains(s)))
        {
            scopedLogger.LogDebug($"Unsupported scopes. Request scopes: {request.Scope}. Refresh token allows: {accessScope}");
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "One or more requested scopes are not part of the original refresh token scopes");
        }

        if (!application.RedirectUris.Contains(redirectUri))
        {
            scopedLogger.LogDebug($"Unsupported redirect uri. Request redirect uri: {redirectUri}. Application allows: {string.Join('\n', application.RedirectUris)}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Unsupported redirect uri");
        }

        var user = await this.userService.GetUserById(userIdentifier.ToString(), cancellationToken);
        if (user is null)
        {
            scopedLogger.LogError($"Could not find user {userIdentifier}");
            return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Invalid refresh token");
        }

        var oauthRequest = new OAuthRequest
        {
            ClientId = applicationIdentifier.ToString(),
            ResponseType = "token",
            UserId = user.Id.ToString(),
            Username = user.Username,
            Scopes = request.Scope ?? accessScope.Replace("offline_access", "").Trim(),
            RedirectUri = redirectUri,
            State = string.Empty,
            Nonce = request.Nonce,
            ClientSecret = clientSecret
        };

        return await this.HandleRequest(oauthRequest, cancellationToken);
    }

    private async Task<Result<OAuthResponse>> GetOAuthTokenFromCodeInternal(OAuthTokenRequest request, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        var validation = this.ValidateTokenRequest(request);
        if (validation is Result<bool>.Failure failure)
        {
            scopedLogger.LogDebug($"Validation failed. Error message: {failure.ErrorMessage}");
            return Result.Failure<OAuthResponse>(errorCode: failure.ErrorCode, errorMessage: failure.ErrorMessage);
        }

        var oauthCode = await this.oAuthCodeDatabase.GetOAuthCode(request.Code.ThrowIfNull(), cancellationToken);
        if (oauthCode is null)
        {
            scopedLogger.LogDebug($"Provided code is invalid");
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Invalid code");
        }

        if (DateTime.UtcNow > oauthCode.NotAfter)
        {
            scopedLogger.LogDebug($"Code is expired");
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Expired code");
        }

        if (Identifier.TryParse<ApplicationIdentifier>(request.ClientId, out var parsedIdentifier) &&
            parsedIdentifier != oauthCode.ClientId)
        {
            scopedLogger.LogDebug($"Client id does not match id from oauth code");
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Provided client id does not match initial client id");
        }

        if (oauthCode.Redirect != request.RedirectUri)
        {
            scopedLogger.LogDebug($"Redirect uri does not match uri from oauth code");
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Redirect uri does not match expected uri");
        }

        if (oauthCode.CodeChallengeMethod is not CodeChallengeMethods.None)
        {
            if (request.CodeVerifier is null)
            {
                scopedLogger.LogDebug($"Code challenge exists but not code verifier was provided");
                return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Missing code verifier");
            }

            if (oauthCode.CodeChallengeMethod is CodeChallengeMethods.Plain &&
                request.CodeVerifier != oauthCode.CodeChallenge)
            {
                scopedLogger.LogDebug($"Code verifier failed verification");
                return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Could not verify code verifier");
            }

            if (oauthCode.CodeChallengeMethod is CodeChallengeMethods.S256 or CodeChallengeMethods.S384 or CodeChallengeMethods.S512)
            {
                var hashAlgorithm = oauthCode.CodeChallengeMethod switch
                {
                    CodeChallengeMethods.S256 => (HashAlgorithm)SHA256.Create(),
                    CodeChallengeMethods.S384 => (HashAlgorithm)SHA384.Create(),
                    CodeChallengeMethods.S512 => (HashAlgorithm)SHA512.Create(),
                    _ => throw new InvalidOperationException($"Unknown code challenge method {oauthCode.CodeChallengeMethod}")
                };

                var verifierBytes = Encoding.UTF8.GetBytes(request.CodeVerifier);
                var hashedBytes = hashAlgorithm.ComputeHash(verifierBytes, 0, verifierBytes.Length);
                var verifierString = BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
                if (verifierString != oauthCode.CodeChallenge)
                {
                    scopedLogger.LogDebug($"Code verifier failed verification");
                    return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Could not verify code verifier");
                }
            }
        }

        var oauthRequest = new OAuthRequest
        {
            ClientId = request.ClientId,
            ResponseType = "token",
            UserId = oauthCode.UserId.ToString(),
            Username = oauthCode.Username,
            Scopes = oauthCode.Scope,
            RedirectUri = oauthCode.Redirect,
            State = oauthCode.State,
            Nonce = request.Nonce,
            ClientSecret = request.ClientSecret
        };

        if (!await this.oAuthCodeDatabase.ExpireOAuthCode(request.Code, cancellationToken))
        {
            scopedLogger.LogError($"Failed to expire OAuth code");
            return Result.Failure<OAuthResponse>(errorCode: 500, errorMessage: "Could not generate token");
        }

        return await this.HandleRequest(oauthRequest, cancellationToken);
    }

    private async Task<Result<OAuthResponse>> HandleRequest(OAuthRequest oAuthRequest, CancellationToken cancellationToken)
    {
        var responseBuilder = OAuthResponseBuilder.CreateOAuthResponse(oAuthRequest.Scopes.ThrowIfNull(), oAuthRequest.State.ThrowIfNull());
        foreach (var handler in this.requestHandlers)
        {
            var result = await handler.Handle(oAuthRequest, responseBuilder, cancellationToken);
            if (result is Result<bool>.Failure resultFailure)
            {
                return new Result<OAuthResponse>.Failure(errorCode: resultFailure.ErrorCode, errorMessage: resultFailure.ErrorMessage);
            }
        }

        return Result.Success(responseBuilder.Build());
    }

    private async Task<Result<bool>> ValidateRequest(OAuthRequest oAuthRequest, CancellationToken cancellationToken)
    {
        if (oAuthRequest.Username is not string username)
        {
            return Result.Failure<bool>(401, "Authentication missing");
        }

        if (oAuthRequest.UserId is not string userId)
        {
            return Result.Failure<bool>(401, "Authentication missing");
        }

        if (!Identifier.TryParse<UserIdentifier>(userId, out var userIdentifier) ||
            userIdentifier is null)
        {
            return Result.Failure<bool>(500, "Invalid user id");
        }

        if (oAuthRequest.ClientId is not string clientId)
        {
            return Result.Failure<bool>(400, "Missing client id");
        }

        if (!Identifier.TryParse<ApplicationIdentifier>(clientId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid client id");
        }

        if (oAuthRequest.Scopes is not string scopes)
        {
            return Result.Failure<bool>(400, "Missing scopes");
        }

        if (oAuthRequest.RedirectUri is not string redirectUri)
        {
            return Result.Failure<bool>(400, "Missing redirect uri");
        }

        if (oAuthRequest.State is not string state)
        {
            return Result.Failure<bool>(400, "Missing state");
        }

        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
        {
            return Result.Failure<bool>(400, "Invalid redirect uri");
        }

        var application = await this.applicationDatabase.GetApplicationById(applicationIdentifier, cancellationToken);
        if (application is null)
        {
            return Result.Failure<bool>(400, $"Unknown client id {applicationIdentifier}");
        }

        if (application.RedirectUris.None(r => r == redirectUri))
        {
            return Result.Failure<bool>(400, $"Unknown redirect uri {redirectUri}");
        }

        var applicationScopes = application.Scopes;
        var requestedScopes = scopes.Split(' ');

        // Ensure that the requested scopes are whitelisted in the application scopes
        if (requestedScopes.FirstOrDefault(scope => !applicationScopes.Contains(scope)) is string unknownScope)
        {
            return Result.Failure<bool>(400, $"Unknown scope {unknownScope}");
        }

        // Ensure that the requested scopes are supported by Badge in configuration
        if (requestedScopes.FirstOrDefault(scope => this.options.ScopesSupported?.FirstOrDefault(s => s.Name == scope) is null) is string unsupportedScope)
        {
            return Result.Failure<bool>(400, $"Unsupported scope {unsupportedScope}. Badge supports the following scopes: {string.Join(", ", this.options.ScopesSupported?.Select(s => s.Name) ?? [])}");
        }

        return Result.Success(true);
    }

    private Result<bool> ValidateTokenRequest(OAuthTokenRequest request)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (request.GrantType is "authorization_code" &&
            this.options.GrantTypesSupported?.Contains("authorization_code") is true)
        {
            if (request.Code is null)
            {
                scopedLogger.LogDebug("Missing code");
                return Result.Failure<bool>(errorCode: 400, errorMessage: "Missing code");
            }

            if (request.ClientId is null)
            {
                scopedLogger.LogDebug($"Missing client id");
                return Result.Failure<bool>(errorCode: 400, errorMessage: "Missing client id");
            }

            if (!Identifier.TryParse<ApplicationIdentifier>(request.ClientId, out var parsedIdentifier))
            {
                scopedLogger.LogDebug($"Could not parse client id {request.ClientId}");
                return Result.Failure<bool>(errorCode: 400, errorMessage: "Invalid client id");
            }

            if (request.RedirectUri is null)
            {
                scopedLogger.LogDebug($"Missing redirect uri");
                return Result.Failure<bool>(errorCode: 400, errorMessage: "Missing redirect uri");
            }

            if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out _))
            {
                scopedLogger.LogDebug($"Invalid redirect uri");
                return Result.Failure<bool>(errorCode: 400, errorMessage: "Invalid redirect uri");
            }
        }
        else if (request.GrantType is "refresh_token" &&
            this.options.GrantTypesSupported?.Contains("refresh_token") is true)
        {
            if (request.RefreshToken is null)
            {
                scopedLogger.LogDebug("Missing refresh_token");
                return Result.Failure<bool>(errorCode: 400, errorMessage: "Missing refresh_token");
            }
        }
        else
        {
            return Result.Failure<bool>(errorCode: 400, errorMessage: $"Unsupported grant type {request.GrantType}");
        }

        return Result.Success(true);
    }

    private async Task<JsonWebKeySetResponse> GetJsonWebKeySetInternal()
    {
        var certificatePairs = await this.certificateService.GetSigningCertificates(CancellationToken.None);
        return new JsonWebKeySetResponse
        {
            Keys = certificatePairs.Select(kvp =>
            {
                var keyDict = new Dictionary<string, string?>
                {
                    ["kid"] = kvp.Key.ToString(),
                    ["use"] = "sig"
                };

                if (kvp.Value.GetRSAPublicKey() is RSA rsa)
                {
                    var p = rsa.ExportParameters(false);
                    keyDict["kty"] = "RSA";
                    keyDict["n"] = p.Modulus is not null ? Convert.ToBase64String(p.Modulus) : string.Empty;
                    keyDict["e"] = p.Exponent is not null ? Convert.ToBase64String(p.Exponent) : string.Empty;
                }
                else if (kvp.Value.GetDSAPublicKey() is DSA dsa)
                {
                    var p = dsa.ExportParameters(false);
                    keyDict["kty"] = "DSA";
                    keyDict["p"] = p.P is not null ? Convert.ToBase64String(p.P) : string.Empty;
                    keyDict["q"] = p.Q is not null ? Convert.ToBase64String(p.Q) : string.Empty;
                    keyDict["g"] = p.G is not null ? Convert.ToBase64String(p.G) : string.Empty;
                    keyDict["y"] = p.Y is not null ? Convert.ToBase64String(p.Y) : string.Empty;
                }
                else if (kvp.Value.GetECDsaPublicKey() is ECDsa ecdsa)
                {
                    var p = ecdsa.ExportParameters(false);
                    keyDict["kty"] = "EC";
                    keyDict["crv"] = GetCurveName(p.Curve);
                    keyDict["x"] = p.Q.X is not null ? Convert.ToBase64String(p.Q.X) : string.Empty;
                    keyDict["y"] = p.Q.Y is not null ? Convert.ToBase64String(p.Q.Y) : string.Empty;
                }

                return keyDict;
            }).ToList()
        };
    }

    private static string GetCurveName(ECCurve curve)
    {
        return curve.Oid.Value switch
        {
            "1.2.840.10045.3.1.7" => "P-256",   // NIST P-256 / secp256r1
            "1.3.132.0.34" => "P-384",          // NIST P-384 / secp384r1
            "1.3.132.0.35" => "P-521",          // NIST P-521 / secp521r1
            _ => throw new ArgumentOutOfRangeException(nameof(curve), "Unsupported curve.")
        };
    }
}
