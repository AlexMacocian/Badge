using System.Text.Json.Serialization;

namespace Badge.Services.OAuth2.Models;

public sealed class OAuthResponse(
    string state,
    string responseType,
    string scope,
    int? expiresIn,
    string? idToken,
    string? code,
    string? accessToken,
    string? tokenType,
    string? refreshToken)
{
    [JsonPropertyName("state")]
    public string State { get; } = state;
    [JsonPropertyName("response_type")]
    public string ResponseType { get; } = responseType;
    [JsonPropertyName("scope")]
    public string Scope { get; } = scope;
    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; } = expiresIn;

    [JsonPropertyName("id_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdToken { get; } = idToken;

    [JsonPropertyName("code")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Code { get; } = code;
    

    [JsonPropertyName("access_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Token { get; } = accessToken;
    [JsonPropertyName("token_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenType { get; } = tokenType;
    
    [JsonPropertyName("refresh_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RefreshToken { get; } = refreshToken;
}
