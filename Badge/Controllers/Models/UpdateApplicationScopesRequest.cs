using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public class UpdateApplicationScopesRequest
{
    [JsonPropertyName("scopes")]
    public List<string>? Scopes { get; set; }
}
