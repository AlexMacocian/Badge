using System.Text.Json.Serialization;

namespace Badge.Models;

public sealed class OAuthDiscoveryDocument(
    string issuer,
    string authorizationEndpoint,
    string tokenEndpoint,
    string userInfoEndpoint,
    string jwksUri,
    List<string> responseTypesSupported,
    List<string> subjectTypesSupported,
    List<string> idTokenSigningAlgValuesSupported,
    List<string> scopesSupported,
    List<string> tokenEndpointAuthMethodsSupported,
    List<string> grantTypesSupported,
    List<string> claimsSupported)
{
    [JsonPropertyName("issuer")]
    public string Issuer { get; } = issuer;
    [JsonPropertyName("authorization_endpoint")]
    public string AuthorizationEndpoint { get; } = authorizationEndpoint;
    [JsonPropertyName("token_endpoint")]
    public string TokenEndpoint { get; } = tokenEndpoint;
    [JsonPropertyName("userinfo_endpoint")]
    public string UserInfoEndpoint { get; } = userInfoEndpoint;
    [JsonPropertyName("jwks_uri")]
    public string JwksUri { get; } = jwksUri;
    [JsonPropertyName("response_types_supported")]
    public List<string> ResponseTypesSupported { get; } = responseTypesSupported;
    [JsonPropertyName("subect_types_supported")]
    public List<string> SubjectTypesSupported { get; } = subjectTypesSupported;
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public List<string> IdTokenSigningAlgValuesSupported { get; } = idTokenSigningAlgValuesSupported;
    [JsonPropertyName("scopes_supported")]
    public List<string> ScopesSupported { get; } = scopesSupported;
    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public List<string> TokenEndpointAuthMethodsSupported { get; } = tokenEndpointAuthMethodsSupported;
    [JsonPropertyName("grant_types_supported")]
    public List<string> GrantTypesSupported { get; } = grantTypesSupported;
    [JsonPropertyName("claims_supported")]
    public List<string> ClaimsSupported { get; } = claimsSupported;
}
