using Badge.Models;
using System.Security.Claims;

namespace Badge.Services.JWT;

public interface IJWTService
{
    Task<JwtToken?> GetToken(string subjectId, CancellationToken cancellationToken);
    Task<ClaimsPrincipal?> ValidateToken(string token, CancellationToken cancellationToken);
}
