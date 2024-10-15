using Badge.Models;
using Badge.Options;
using Badge.Services.Certificates;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
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

    private readonly ICertificateService certificateService;
    private readonly JWTServiceOptions jwtServiceOptions;
    private readonly ILogger<JWTService> logger;

    public JWTService(
        ICertificateService certificateService,
        IOptions<JWTServiceOptions> options,
        ILogger<JWTService> logger)
    {
        this.certificateService = certificateService.ThrowIfNull();
        this.jwtServiceOptions = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<JwtToken?> GetLoginToken(string subjectId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, subjectId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            return await this.GetTokenFromClaims(claims, cancellationToken);
        }
        catch(Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while getting token");
            throw;
        }
    }

    public async Task<JwtToken?> GetOAuthToken(
        string subjectId,
        string clientId,
        string scope,
        CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, subjectId),
                new Claim(JwtRegisteredClaimNames.Aud, clientId),
                new Claim(JwtRegisteredClaimNames.Iss, this.jwtServiceOptions.Issuer),
                new Claim("scope", scope),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            return await this.GetTokenFromClaims(claims, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while getting token");
            throw;
        }
    }

    public async Task<JwtToken?> GetOpenIDToken(
        string subjectId,
        string clientId,
        string scope,
        string nonce,
        string accessToken,
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

            var signingAlgorithm = privateKey.SignatureAlgorithm;
            if (signingAlgorithm is null)
            {
                throw new InvalidOperationException("Signing certificate does not have a valid hashing algorithm");
            }

            var rsa = signingAlgorithm switch
            {
                "SHA512" => (HashAlgorithm)SHA512.Create(),
                "SHA384" => (HashAlgorithm)SHA384.Create(),
                "SHA245" => (HashAlgorithm)SHA256.Create(),
                "SHA1" => (HashAlgorithm)SHA1.Create(),
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
                new Claim(JwtRegisteredClaimNames.Sub, subjectId),
                new Claim(JwtRegisteredClaimNames.Aud, clientId),
                new Claim(JwtRegisteredClaimNames.Iss, this.jwtServiceOptions.Issuer),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.AuthTime, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("scope", scope),
                new Claim("nonce", nonce),
                new Claim("at_hash", tokenHash)
            };

            return await this.GetTokenFromClaims(claims, cancellationToken);
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while getting token");
            throw;
        }
    }

    public async Task<ClaimsPrincipal?> ValidateToken(string token, CancellationToken cancellationToken)
    {
        try
        {
            return await this.ValidateJwtInternal(token, cancellationToken);
        }
        catch (SecurityTokenArgumentException)
        {
            return default;
        }
        catch (SecurityTokenException)
        {
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

    private async Task<JwtToken?> GetTokenFromClaims(Claim[] claims, CancellationToken cancellationToken)
    {
        var signingKey = await this.certificateService.GetSigningCertificate(cancellationToken);
        var privateKey = signingKey.GetRSAPrivateKey();
        var signingCredentials = new SigningCredentials(new RsaSecurityKey(privateKey), this.jwtServiceOptions.SigningAlgorithm);

        var expires = DateTime.UtcNow.Add(this.jwtServiceOptions.Validity);
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

    private async Task<ClaimsPrincipal?> ValidateJwtInternal(string token, CancellationToken cancellationToken)
    {
        var keys = new List<SecurityKey>();
        foreach (var cert in await this.certificateService.GetSigningCertificates(cancellationToken))
        {
            var rsa = cert.Value.GetRSAPublicKey();
            if (rsa is not null)
            {
                keys.Add(new RsaSecurityKey(rsa));
            }
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
        return principal;
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return System.Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .Replace("=", "");
    }
}
