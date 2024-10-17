using Badge.Models;
using Badge.Models.JsonWebKeys;
using Badge.Services.OAuth2.Models;

namespace Badge.Services.OAuth2;

public interface IOAuth2Service
{
    IEnumerable<OAuthScope> GetOAuthScopes();
    Task<JsonWebKeySetResponse> GetJsonWebKeySet(CancellationToken cancellationToken);
    Task<Result<OAuthResponse>> GetAuthorization(OAuthRequest oAuthRequest, CancellationToken cancellationToken);
    Task<OAuthDiscoveryDocument> GetOAuthDiscoveryDocument(CancellationToken cancellationToken);
    Task<Result<OAuthResponse>> GetOAuthToken(OAuthTokenRequest request, CancellationToken cancellationToken);
}
