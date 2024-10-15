using Badge.Models;
using System.Security.Claims;

namespace Badge.Services.JWT;

public interface IJWTService
{
    Task<JwtToken?> GetLoginToken(string subjectId, CancellationToken cancellationToken);
    Task<JwtToken?> GetOAuthToken(string subjectId, string clientId, string scope, CancellationToken cancellationToken);
    Task<JwtToken?> GetOpenIDToken(string subjectId, string clientId, string scope, string nonce, string accessToken, CancellationToken cancellationToken);
    Task<ClaimsPrincipal?> ValidateToken(string token, CancellationToken cancellationToken);
    string GetSigningAlg();
    string GetIssuer();
}
