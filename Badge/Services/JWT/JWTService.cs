using Badge.Models;
using Badge.Options;
using Badge.Services.Certificates;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Cache;
using System.Core.Extensions;
using System.Extensions;
using System.Extensions.Core;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Badge.Services.JWT;

public sealed class JWTService : IJWTService
{
    private static readonly JwtSecurityTokenHandler DefaultHandler = new();

    private readonly AsyncValueCache<List<SecurityKey>> securityKeysCache;
    private readonly ICertificateService certificateService;
    private readonly JWTServiceOptions jwtServiceOptions;
    private readonly ILogger<JWTService> logger;

    public JWTService(
        ICertificateService certificateService,
        IOptions<JWTServiceOptions> options,
        ILogger<JWTService> logger)
    {
        this.securityKeysCache = new(this.GetSigngingKeys, TimeSpan.FromMinutes(5));
        this.certificateService = certificateService.ThrowIfNull();
        this.jwtServiceOptions = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<JwtToken?> GetLoginToken(string userId, string username, TimeSpan duration, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.PreferredUsername, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtExtendedClaimNames.TokenType, OAuthTokenTypes.LoginToken),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            return await this.GetTokenFromClaims(claims, duration, cancellationToken);
        }
        catch(Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while getting token");
            throw;
        }
    }

    public async Task<JwtToken?> GetAccessToken(
        string subjectId,
        string clientId,
        string username,
        string scope,
        TimeSpan duration,
        CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, subjectId),
                new Claim(JwtRegisteredClaimNames.Aud, clientId),
                new Claim(JwtRegisteredClaimNames.PreferredUsername, username),
                new Claim(JwtRegisteredClaimNames.Iss, this.jwtServiceOptions.Issuer),
                new Claim(JwtExtendedClaimNames.Scope, scope),
                new Claim(JwtExtendedClaimNames.TokenType, OAuthTokenTypes.AccessToken),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            return await this.GetTokenFromClaims(claims, duration, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while getting token");
            throw;
        }
    }

    public async Task<JwtToken?> GetRefreshToken(
        string userId,
        string clientId,
        string scope,
        string redirectUri,
        string clientSecret,
        TimeSpan duration,
        CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Aud, clientId),
                new Claim(JwtRegisteredClaimNames.Iss, this.jwtServiceOptions.Issuer),
                new Claim(JwtExtendedClaimNames.AccessScope, scope),
                new Claim(JwtExtendedClaimNames.Scope, "offline_access"),
                new Claim(JwtExtendedClaimNames.TokenType, OAuthTokenTypes.RefreshToken),
                new Claim(JwtExtendedClaimNames.RedirectUri, redirectUri),
                new Claim(JwtExtendedClaimNames.ClientSecret, clientSecret),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            return await this.GetTokenFromClaims(claims, duration, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while getting token");
            throw;
        }
    }

    public async Task<JwtToken?> GetOpenIDToken(
        string userId,
        string clientId,
        string username,
        string scope,
        string nonce,
        string accessToken,
        TimeSpan duration,
        CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            var signingKey = await this.certificateService.GetSigningCertificate(cancellationToken);
            var privateKey = signingKey.GetRSAPrivateKey();
            if (privateKey is null)
            {
                throw new InvalidOperationException("Unable to get signing certificate");
            }

            var signingAlgorithm = signingKey.SignatureAlgorithm.FriendlyName;
            if (signingAlgorithm is null)
            {
                throw new InvalidOperationException("Signing certificate does not have a valid hashing algorithm");
            }

            var rsa = signingAlgorithm switch
            {
                "sha512RSA" => (HashAlgorithm)SHA512.Create(),
                "sha384RSA" => (HashAlgorithm)SHA384.Create(),
                "sha245RSA" => (HashAlgorithm)SHA256.Create(),
                "sha1RSA" => (HashAlgorithm)SHA1.Create(),
                _ => throw new InvalidOperationException($"Unsupported hashing algorithm {signingAlgorithm}")
            };

            if (rsa is null)
            {
                throw new InvalidOperationException("Unable to create hashing algorithm");
            }

            var accessTokenHash = rsa.ComputeHash(Encoding.UTF8.GetBytes(accessToken));
            var hashSize = accessTokenHash.Length / 2;
            var leftmostBytes = new byte[hashSize];
            Array.Copy(accessTokenHash, leftmostBytes, hashSize);
            var tokenHash = Base64UrlEncode(leftmostBytes);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Aud, clientId),
                new Claim(JwtRegisteredClaimNames.PreferredUsername, username),
                new Claim(JwtRegisteredClaimNames.Iss, this.jwtServiceOptions.Issuer),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.AuthTime, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtExtendedClaimNames.Scope, scope),
                new Claim(JwtExtendedClaimNames.Nonce, nonce),
                new Claim(JwtExtendedClaimNames.AccessTokenHash, tokenHash),
                new Claim(JwtExtendedClaimNames.TokenType, OAuthTokenTypes.OpenIdToken)
            };

            return await this.GetTokenFromClaims(claims, duration, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while getting token");
            throw;
        }
    }

    public async Task<ValidatedIdentity?> ValidateToken(string token, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.ValidateJwtInternal(token, cancellationToken);
        }
        catch (SecurityTokenArgumentException ex)
        {
            scopedLogger.LogError(ex, "Failed to validate jwt");
            return default;
        }
        catch (SecurityTokenException ex)
        {
            scopedLogger.LogError(ex, "Failed to validate jwt");
            return default;
        }
    }

    public string GetSigningAlg()
    {
        return this.jwtServiceOptions.SigningAlgorithm;
    }

    public string GetIssuer()
    {
        return this.jwtServiceOptions.Issuer;
    }

    private async Task<JwtToken?> GetTokenFromClaims(Claim[] claims, TimeSpan duration, CancellationToken cancellationToken)
    {
        var signingKey = await this.certificateService.GetSigningCertificate(cancellationToken);
        var privateKey = signingKey.GetRSAPrivateKey();
        var signingCredentials = new SigningCredentials(new RsaSecurityKey(privateKey), this.jwtServiceOptions.SigningAlgorithm);

        var expires = DateTime.UtcNow.Add(duration);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expires,
            SigningCredentials = signingCredentials,
            Issuer = this.jwtServiceOptions.Issuer,
            Audience = this.jwtServiceOptions.Audience
        };

        var token = DefaultHandler.CreateToken(tokenDescriptor);
        var jwtToken = DefaultHandler.WriteToken(token);
        return new JwtToken(jwtToken, expires);
    }

    private async Task<ValidatedIdentity?> ValidateJwtInternal(string token, CancellationToken _)
    {
        var keys = await this.securityKeysCache.GetValue();
        if (keys.Count == 0)
        {
            return default;
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = this.jwtServiceOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = this.jwtServiceOptions.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) => keys
        };

        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
        if (principal.Identity is not CaseSensitiveClaimsIdentity identity ||
            identity.SecurityToken is not JwtSecurityToken securityToken)
        {
            return default;
        }

        return new ValidatedIdentity(securityToken, principal);
    }

    private async Task<List<SecurityKey>> GetSigngingKeys()
    {
        var keys = new List<SecurityKey>();
        foreach (var cert in await this.certificateService.GetSigningCertificates(CancellationToken.None))
        {
            var rsa = cert.Value.GetRSAPublicKey();
            if (rsa is not null)
            {
                keys.Add(new RsaSecurityKey(rsa));
            }
        }

        return keys;
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return System.Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }
}
