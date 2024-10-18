using Badge.Models;

namespace Badge.Services.JWT;

public interface IJWTService
{
    Task<JwtToken?> GetLoginToken(string userId, string username, TimeSpan duration, CancellationToken cancellationToken);
    Task<JwtToken?> GetAccessToken(string userId, string clientId, string username, string scope, TimeSpan duration, CancellationToken cancellationToken);
    Task<JwtToken?> GetRefreshToken(string userId, string clientId, string scope, string redirectUri, string clientSecret, TimeSpan duration, CancellationToken cancellationToken);
    Task<JwtToken?> GetOpenIDToken(string userId, string clientId, string username, string scope, string nonce, string accessToken, TimeSpan duration, CancellationToken cancellationToken);
    Task<ValidatedIdentity?> ValidateToken(string token, CancellationToken cancellationToken);
    string GetSigningAlg();
    string GetIssuer();
}
