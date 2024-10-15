using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public sealed class OAuthScopeResponse
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
    [JsonPropertyName("description")]
    public string? Description { get; set; }
}
