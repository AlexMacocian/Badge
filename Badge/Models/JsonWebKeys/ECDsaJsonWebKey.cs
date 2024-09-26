using System.Text.Json.Serialization;

namespace Badge.Models.JsonWebKeys;

public class ECDsaJsonWebKey : JsonWebKey
{
    [JsonPropertyName("crv")]
    public string? Curve
    {
        get => this["crv"];
        set => this["crv"] = value;
    }
    [JsonPropertyName("x")]
    public string? X
    {
        get => this["x"];
        set => this["x"] = value;
    }
    [JsonPropertyName("y")]
    public string? Y
    {
        get => this["y"];
        set => this["y"] = value;
    }
}
