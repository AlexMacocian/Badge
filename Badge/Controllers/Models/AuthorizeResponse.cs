using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public sealed class AuthorizeResponse
{
    [JsonPropertyName("code")]
    public string? Code { get; set; }
    [JsonPropertyName("state")]
    public string? State { get; set; }
}
