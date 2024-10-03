using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public sealed class ApplicationResponse
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    [JsonPropertyName("logoBase64")]
    public string? LogoBase64 { get; set; }
    [JsonPropertyName("scopes")]
    public List<string>? Scopes { get; set; }
    [JsonPropertyName("owned")]
    public bool Owned { get; set; }
    [JsonPropertyName("creationDate")]
    public DateTime CreationDate { get; set; }
}
