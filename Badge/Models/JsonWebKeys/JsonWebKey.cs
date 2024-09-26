using System.Text.Json.Serialization;

namespace Badge.Models.JsonWebKeys;

public abstract class JsonWebKey : Dictionary<string, string?>
{
    [JsonPropertyName("kty")]
    public string? Type
    {
        get => this["kty"];
        set => this["kty"] = value;
    }
    [JsonPropertyName("kid")]
    public string? Id
    {
        get => this["kid"];
        set => this["kid"] = value;
    }
    [JsonPropertyName("use")]
    public string? Use
    {
        get => this["use"];
        set => this["use"] = value;
    }
}
