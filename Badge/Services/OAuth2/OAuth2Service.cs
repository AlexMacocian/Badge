using Badge.Models;
using Badge.Models.Identity;
using Badge.Models.JsonWebKeys;
using Badge.Options;
using Badge.Services.Applications;
using Badge.Services.Certificates;
using Badge.Services.Database.Applications;
using Badge.Services.Database.OAuth;
using Badge.Services.JWT;
using Badge.Services.OAuth2.Handlers;
using Badge.Services.OAuth2.Models;
using Badge.Services.Passwords;
using Microsoft.Extensions.Options;
using System.Cache;
using System.Collections;
using System.Core.Extensions;
using System.Extensions;
using System.Extensions.Core;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Convert = System.Convert;

namespace Badge.Services.OAuth2;

public sealed class OAuth2Service : IOAuth2Service
{
    private static AsyncValueCache<JsonWebKeySetResponse>? JsonWebKeySets;

    private readonly IEnumerable<IOAuthRequestHandler> requestHandlers;
    private readonly IJWTService jWTService;
    private readonly IApplicationDatabase applicationDatabase;
    private readonly IApplicationService applicationService;
    private readonly IOAuthCodeDatabase oAuthCodeDatabase;
    private readonly ICertificateService certificateService;
    private readonly IPasswordService passwordService;
    private readonly OAuthServiceOptions options;
    private readonly ILogger<OAuth2Service> logger;

    public OAuth2Service(
        IEnumerable<IOAuthRequestHandler> requestHandlers,
        IJWTService jWTService,
        IApplicationDatabase applicationDatabase,
        IApplicationService applicationService,
        IOAuthCodeDatabase oAuthCodeDatabase,
        ICertificateService certificateService,
        IPasswordService passwordService,
        IOptions<OAuthServiceOptions> options,
        ILogger<OAuth2Service> logger)
    {
        this.requestHandlers = requestHandlers.ThrowIfNull();
        this.jWTService = jWTService.ThrowIfNull();
        this.applicationDatabase = applicationDatabase.ThrowIfNull();
        this.applicationService = applicationService.ThrowIfNull();
        this.oAuthCodeDatabase = oAuthCodeDatabase.ThrowIfNull();
        this.certificateService = certificateService.ThrowIfNull();
        this.passwordService = passwordService.ThrowIfNull();
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();

        //TODO: Not exactly correct, as there's up to 5 minutes that a new signing key will not be reflected in this cache
        JsonWebKeySets ??= new AsyncValueCache<JsonWebKeySetResponse>(this.GetJsonWebKeySetInternal, this.options.KeySetCacheDuration);
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

    public async Task<Result<OAuthResponse>> GetOAuthTokenFromCode(string? code, string? clientId, string? grantType, string? redirectUri, string? codeVerifier, string? nonce, CancellationToken cancellationToken)
    {
        return await this.GetOAuthTokenFromCodeInternal(code, clientId, codeVerifier, grantType, redirectUri, nonce, cancellationToken);
    }

    public Task<OAuthDiscoveryDocument> GetOAuthDiscoveryDocument(CancellationToken cancellationToken)
    {
        return Task.FromResult(new OAuthDiscoveryDocument(
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
            claimsSupported: ["sub"]));
    }

    public IEnumerable<OAuthScope> GetOAuthScopes()
    {
        return this.options.ScopesSupported?.ToList() ?? Enumerable.Empty<OAuthScope>();
    }

    private async Task<Result<OAuthResponse>> GetOAuthTokenFromCodeInternal(
        string? code,
        string? clientId,
        string? codeVerifier,
        string? grantType,
        string? redirectUri,
        string? nonce,
        CancellationToken cancellationToken)
    {
        if (code is null)
        {
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Missing code");
        }

        if (grantType is not "authorization_code")
        {
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Grant type unsupported");
        }

        if (redirectUri is null)
        {
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Missing redirect uri");
        }

        var oauthCode = await this.oAuthCodeDatabase.GetOAuthCode(code, cancellationToken);
        if (oauthCode is null)
        {
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Invalid code");
        }

        if (DateTime.UtcNow > oauthCode.NotAfter)
        {
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Expired code");
        }

        if (!Identifier.TryParse<ApplicationIdentifier>(clientId, out var parsedIdentifier))
        {
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Invalid client id");
        }

        if (parsedIdentifier != oauthCode.ClientId)
        {
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Provided client id does not match initial client id");
        }

        if (oauthCode.CodeChallengeMethod is not CodeChallengeMethods.None)
        {
            if (codeVerifier is null)
            {
                return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Missing code verifier");
            }

            if (oauthCode.CodeChallengeMethod is CodeChallengeMethods.Plain &&
                codeVerifier != oauthCode.CodeChallenge)
            {
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

                var verifierBytes = Encoding.UTF8.GetBytes(codeVerifier);
                var hashedBytes = hashAlgorithm.ComputeHash(verifierBytes, 0, verifierBytes.Length);
                var verifierString = BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
                if (verifierString != oauthCode.CodeChallenge)
                {
                    return Result.Failure<OAuthResponse>(errorCode: 401, errorMessage: "Could not verify code verifier");
                }
            }
        }

        if (oauthCode.Redirect != redirectUri)
        {
            return Result.Failure<OAuthResponse>(errorCode: 400, errorMessage: "Redirect uri does not match expected uri");
        }

        var oauthRequest = new OAuthRequest
        {
            ClientId = clientId,
            ResponseType = "token",
            UserId = oauthCode.UserId.ToString(),
            Username = oauthCode.Username,
            Scopes = oauthCode.Scope,
            RedirectUri = oauthCode.Redirect,
            State = oauthCode.State,
            Nonce = nonce
        };

        //TODO: Delete OAuth code after successful usage
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

        if (oAuthRequest.ClientSecret is not string clientSecret)
        {
            return Result.Failure<bool>(400, "Missing client secret");
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

        var applicationSecretsResult = await this.applicationService.GetClientSecrets(clientId, cancellationToken);
        if (applicationSecretsResult is Result<List<ClientSecret>>.Failure failure)
        {
            return Result.Failure<bool>(failure.ErrorCode, failure.ErrorMessage);
        }

        var applicationSecrets = applicationSecretsResult.Cast<Result<List<ClientSecret>>.Success>().Result;
        var validSecret = false;
        foreach(var secret in applicationSecrets)
        {
            if (await this.passwordService.Verify(clientSecret, secret.Hash, cancellationToken))
            {
                validSecret = true;
            }
        }

        if (!validSecret)
        {
            return Result.Failure<bool>(401, "Invalid client secret");
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
