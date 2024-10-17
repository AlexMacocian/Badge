using Badge.Models;

namespace Badge.Services.Database.OAuth;

public interface IOAuthCodeDatabase
{
    Task<bool> CreateOAuthCode(OAuthCode code, CancellationToken cancellationToken);
    Task<OAuthCode?> GetOAuthCode(string code, CancellationToken cancellationToken);
    Task<bool> ExpireOAuthCode(string code, CancellationToken cancellationToken);
    Task DeleteExpiredOAuthCodes(DateTime expiration, CancellationToken cancellationToken);
}
