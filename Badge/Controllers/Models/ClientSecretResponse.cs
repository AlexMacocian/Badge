using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public sealed class ClientSecretResponse
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    [JsonPropertyName("detail")]
    public string? Detail { get; set; }
    [JsonPropertyName("creationDate")]
    public DateTime CreationDate { get; set; }
    [JsonPropertyName("expirationDate")]
    public DateTime ExpirationDate { get; set; }
}
