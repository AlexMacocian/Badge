using System.Text.Json.Serialization;

namespace Badge.Services.OAuth2.Models;

public sealed class UserInfoResponse
{
    [JsonPropertyName("sub")]
    public string? UserId { get; set; }
    [JsonPropertyName("preferred_username")]
    public string? Username { get; set; }
}
