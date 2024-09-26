using System.Text.Json.Serialization;

namespace Badge.Models.JsonWebKeys;

public sealed class JsonWebKeySetResponse
{
    [JsonPropertyName("keys")]
    public List<Dictionary<string, string?>>? Keys { get; set; }
}
