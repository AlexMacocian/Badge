using Badge.Models;
using Badge.Services.OAuth2.Models;

namespace Badge.Services.OAuth2.Handlers;

public interface IOAuthRequestHandler
{
    Task<Result<bool>> Handle(OAuthRequest validRequest, OAuthResponseBuilder oAuthResponseBuilder, CancellationToken cancellationToken);
}
