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
using System.Security.Cryptography.X509Certificates;

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

    public async Task<JwtToken?> GetToken(string subjectId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            return await this.GetTokenInternal(subjectId, cancellationToken);
        }
        catch(Exception e)
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

    private async Task<JwtToken?> GetTokenInternal(string subjectId, CancellationToken cancellationToken)
    {
        var signingKey = await this.certificateService.GetSigningCertificate(cancellationToken);
        var privateKey = signingKey.GetRSAPrivateKey();
        var signingCredentials = new SigningCredentials(new RsaSecurityKey(privateKey), this.jwtServiceOptions.SigningAlgorithm);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, subjectId),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

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

    public async Task<ClaimsPrincipal?> ValidateJwtInternal(string token, CancellationToken cancellationToken)
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

    
}
