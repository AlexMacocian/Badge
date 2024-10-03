using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public class UpdateClientSecretDetailRequest
{
    [JsonPropertyName("detail")]
    public string? Detail { get; set; }
}
