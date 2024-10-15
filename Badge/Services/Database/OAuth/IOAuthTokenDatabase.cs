using Badge.Models;

namespace Badge.Services.Database.OAuth;

public interface IOAuthTokenDatabase
{
    Task<bool> CreateOAuthToken(OAuthToken code, CancellationToken cancellationToken);
    Task<OAuthToken?> GetOAuthToken(string code, CancellationToken cancellationToken);
    Task DeleteExpiredOAuthTokens(DateTime expiration, CancellationToken cancellationToken);
}
