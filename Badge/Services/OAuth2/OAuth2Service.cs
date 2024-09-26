using Badge.Models;
using Badge.Models.JsonWebKeys;
using Badge.Options;
using Badge.Services.Certificates;
using Badge.Services.Database.OAuth;
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

    private readonly OAuthServiceOptions options;
    private readonly IOAuthCodeDatabase oAuthCodeDatabase;
    private readonly ICertificateService certificateService;
    private readonly ILogger<OAuth2Service> logger;

    public OAuth2Service(
        IOptions<OAuthServiceOptions> options,
        IOAuthCodeDatabase oAuthCodeDatabase,
        ICertificateService certificateService,
        ILogger<OAuth2Service> logger)
    {
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

    public async Task<OAuthValidationResponse> ValidateOAuth2Request(OAuthRequest oAuthRequest, CancellationToken cancellationToken)
    {
        if (oAuthRequest.ClientSecret is not string clientSecret)
        {
            return new OAuthValidationResponse.Failure { ErrorCode = 400, ErrorMessage = "Missing client secret" };
        }

        if (oAuthRequest.ClientId is not string clientId)
        {
            return new OAuthValidationResponse.Failure { ErrorCode = 400, ErrorMessage = "Missing client id" };
        }

        if (oAuthRequest.Scopes is not string scopes)
        {
            return new OAuthValidationResponse.Failure { ErrorCode = 400, ErrorMessage = "Missing scopes" };
        }

        if (oAuthRequest.RedirectUri is not string redirectUri)
        {
            return new OAuthValidationResponse.Failure { ErrorCode = 400, ErrorMessage = "Missing redirect uri" };
        }

        if (oAuthRequest.State is not string state)
        {
            return new OAuthValidationResponse.Failure { ErrorCode = 400, ErrorMessage = "Missing state" };
        }

        if (Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
        {
            return new OAuthValidationResponse.Failure { ErrorCode = 400, ErrorMessage = "Invalid redirect uri" };
        }

        var code = Guid.NewGuid().ToString().Replace("-", "");
        var notBefore = DateTime.Now;
        var notAfter = notBefore + this.options.AuthCodeDuration;
        var oauthCode = new OAuthCode(code, notBefore, notAfter);
        if (!await this.oAuthCodeDatabase.CreateOAuthCode(oauthCode, cancellationToken))
        {
            return new OAuthValidationResponse.Failure { ErrorCode = 500, ErrorMessage = "Failed to create oauth code" };
        }

        //TODO: Validate parameters
        return new OAuthValidationResponse.Success() { Code = code, State = state };
    }

    private async Task<JsonWebKeySetResponse> GetJsonWebKeySetInternal()
    {
        var certificatePairs = await this.certificateService.GetSigningCertificates(CancellationToken.None);
        return new JsonWebKeySetResponse
        {
            Keys = certificatePairs.Select(kvp =>
            {
                var keyDict = new Dictionary<string, string?>();
                keyDict["kid"] = kvp.Key;
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

    private string GetCurveName(ECCurve curve)
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
