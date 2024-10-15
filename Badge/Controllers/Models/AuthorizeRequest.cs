using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public class AuthorizeRequest
{
    [JsonPropertyName("clientId")]
    public string? ClientId { get; set; }
    [JsonPropertyName("clientSecret")]
    public string? ClientSecret { get; set; }
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
    [JsonPropertyName("state")]
    public string? State { get; set; }
    [JsonPropertyName("redirectUri")]
    public string? RedirectUri { get; set; }
    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }
}
