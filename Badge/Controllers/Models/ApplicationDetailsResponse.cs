using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public sealed class ApplicationDetailsResponse
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    [JsonPropertyName("logoBase64")]
    public string? LogoBase64 { get; set; }
}
