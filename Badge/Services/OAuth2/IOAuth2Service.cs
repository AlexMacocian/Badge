using Badge.Models;
using Badge.Models.JsonWebKeys;
using Badge.Services.OAuth2.Models;

namespace Badge.Services.OAuth2;

public interface IOAuth2Service
{
    Task<JsonWebKeySetResponse> GetJsonWebKeySet(CancellationToken cancellationToken);
    Task<Result<OAuthValidationResponse>> ValidateOAuth2Request(OAuthRequest oAuthRequest, CancellationToken cancellationToken);
}
