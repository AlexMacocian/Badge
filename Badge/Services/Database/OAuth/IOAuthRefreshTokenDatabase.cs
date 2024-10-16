namespace Badge.Services.Database.OAuth;

public interface IOAuthRefreshTokenDatabase
{
    Task<bool> CreateRefreshToken(string token, DateTime expirationTime, CancellationToken cancellationToken);
    Task<bool> ValidateRefreshToken(string token, CancellationToken cancellationToken);
    Task<bool> DeleteRefreshToken(string token, CancellationToken cancellationToken);
    Task DeleteExpiredOAuthCodes(DateTime expiration, CancellationToken cancellationToken);
}
