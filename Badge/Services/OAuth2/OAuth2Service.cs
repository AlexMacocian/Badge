using Badge.Models;
using Badge.Models.Identity;
using Badge.Models.JsonWebKeys;
using Badge.Options;
using Badge.Services.Applications;
using Badge.Services.Certificates;
using Badge.Services.Database.Applications;
using Badge.Services.Database.OAuth;
using Badge.Services.JWT;
using Badge.Services.OAuth2.Models;
using Microsoft.Extensions.Options;
using System.Cache;
using System.Core.Extensions;
using System.Extensions;
using System.Extensions.Core;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Convert = System.Convert;

namespace Badge.Services.OAuth2;

public sealed class OAuth2Service : IOAuth2Service
{
    private static AsyncValueCache<JsonWebKeySetResponse>? JsonWebKeySets;

    private readonly IJWTService jWTService;
    private readonly IApplicationDatabase applicationDatabase;
    private readonly IApplicationService applicationService;
    private readonly OAuthServiceOptions options;
    private readonly IOAuthCodeDatabase oAuthCodeDatabase;
    private readonly ICertificateService certificateService;
    private readonly ILogger<OAuth2Service> logger;

    public OAuth2Service(
        IJWTService jWTService,
        IApplicationDatabase applicationDatabase,
        IApplicationService applicationService,
        IOptions<OAuthServiceOptions> options,
        IOAuthCodeDatabase oAuthCodeDatabase,
        ICertificateService certificateService,
        ILogger<OAuth2Service> logger)
    {
        this.jWTService = jWTService.ThrowIfNull();
        this.applicationDatabase = applicationDatabase.ThrowIfNull();
        this.applicationService = applicationService.ThrowIfNull();
        this.options = options.ThrowIfNull().Value;
        this.oAuthCodeDatabase = oAuthCodeDatabase.ThrowIfNull();
        this.certificateService = certificateService.ThrowIfNull();
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

    public async Task<Result<OAuthValidationResponse>> ValidateOAuth2Request(OAuthRequest oAuthRequest, CancellationToken cancellationToken)
    {
        if (oAuthRequest.Username is not string username)
        {
            return Result.Failure<OAuthValidationResponse>(401, "User needs to be authenticated to perform the OAuth flow");
        }

        if (oAuthRequest.UserId is not string userId)
        {
            return Result.Failure<OAuthValidationResponse>(401, "User needs to be authenticated to perform the OAuth flow");
        }

        if (!Identifier.TryParse<UserIdentifier>(userId, out var userIdentifier) ||
            userIdentifier is null)
        {
            return Result.Failure<OAuthValidationResponse>(500, "User needs is authenticated but could not resolve user id");
        }

        if (oAuthRequest.ClientSecret is not string clientSecret)
        {
            return Result.Failure<OAuthValidationResponse>(400, "Missing client secret");
        }

        if (oAuthRequest.ClientId is not string clientId)
        {
            return Result.Failure<OAuthValidationResponse>(400, "Missing client id");
        }

        if (!Identifier.TryParse<ApplicationIdentifier>(clientId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<OAuthValidationResponse>(400, "Invalid client id");
        }

        if (oAuthRequest.Scopes is not string scopes)
        {
            return Result.Failure<OAuthValidationResponse>(400, "Missing scopes");
        }

        if (oAuthRequest.RedirectUri is not string redirectUri)
        {
            return Result.Failure<OAuthValidationResponse>(400, "Missing redirect uri");
        }

        if (oAuthRequest.State is not string state)
        {
            return Result.Failure<OAuthValidationResponse>(400, "Missing state");
        }

        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
        {
            return Result.Failure<OAuthValidationResponse>(400, "Invalid redirect uri");
        }

        var application = await this.applicationDatabase.GetApplicationById(applicationIdentifier, cancellationToken);
        if (application is null)
        {
            return Result.Failure<OAuthValidationResponse>(400, $"Unknown client id {applicationIdentifier}");
        }

        if (application.RedirectUris.None(r => r == redirectUri))
        {
            return Result.Failure<OAuthValidationResponse>(400, $"Unknown redirect uri {redirectUri}");
        }

        var applicationScopes = application.Scopes;
        var requestedScopes = scopes.Split(' ');

        // Ensure that the requested scopes are both whitelisted in the application and supported by the service
        if (requestedScopes.FirstOrDefault(scope => !applicationScopes.Contains(scope) || this.options.ScopesSupported?.Contains(scope) is false) is string unknownScope)
        {
            return Result.Failure<OAuthValidationResponse>(400, $"Unknown scope {unknownScope}");
        }

        var code = Guid.NewGuid().ToString().Replace("-", "");
        var notBefore = DateTime.Now;
        var notAfter = notBefore + this.options.AuthCodeDuration;
        var oauthCode = new OAuthCode(code, notBefore, notAfter, username, scopes, redirectUri);
        if (!await this.oAuthCodeDatabase.CreateOAuthCode(oauthCode, cancellationToken))
        {
            return Result.Failure<OAuthValidationResponse>(500, "Failed to create oauth code");
        }

        return Result.Success(new OAuthValidationResponse(code, state));
    }

    public Task<OAuthDiscoveryDocument> GetOAuthDiscoveryDocument(CancellationToken cancellationToken)
    {
        return Task.FromResult(new OAuthDiscoveryDocument(
            this.options.Issuer ?? throw new InvalidOperationException("Issuer is null"),
            $"{this.options.Issuer}/oauth/authorize",
            $"{this.options.Issuer}/api/oauth/token",
            $"{this.options.Issuer}/api/oauth/userinfo",
            $"{this.options.Issuer}/api/oauth/.well-known/jwks.json",
            ["code", "token"],
            ["public"],
            [this.jWTService.GetSigningAlg()],
            this.options.ScopesSupported ?? [],
            ["client_secret_post"],
            ["authorization_code"],
            ["sub"]));
        
    }

    private async Task<JsonWebKeySetResponse> GetJsonWebKeySetInternal()
    {
        var certificatePairs = await this.certificateService.GetSigningCertificates(CancellationToken.None);
        return new JsonWebKeySetResponse
        {
            Keys = certificatePairs.Select(kvp =>
            {
                var keyDict = new Dictionary<string, string?>();
                keyDict["kid"] = kvp.Key.ToString();
                keyDict["use"] = "sig";

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
