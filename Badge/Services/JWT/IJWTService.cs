using Badge.Models;
using System.Security.Claims;

namespace Badge.Services.JWT;

public interface IJWTService
{
    Task<JwtToken?> GetLoginToken(string subjectId, TimeSpan duration, CancellationToken cancellationToken);
    Task<JwtToken?> GetAccessToken(string subjectId, string clientId, string scope, TimeSpan duration, CancellationToken cancellationToken);
    Task<JwtToken?> GetRefreshToken(string subjectId, string clientId, string scope, TimeSpan duration, CancellationToken cancellationToken);
    Task<JwtToken?> GetOpenIDToken(string subjectId, string clientId, string scope, string nonce, string accessToken, TimeSpan duration, CancellationToken cancellationToken);
    Task<ClaimsPrincipal?> ValidateToken(string token, CancellationToken cancellationToken);
    string GetSigningAlg();
    string GetIssuer();
}
