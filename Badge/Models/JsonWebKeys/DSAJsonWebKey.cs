using System.Text.Json.Serialization;

namespace Badge.Models.JsonWebKeys;

public class DSAJsonWebKey : JsonWebKey
{
    [JsonPropertyName("p")]
    public string? P
    {
        get => this["p"];
        set => this["p"] = value;
    }
    [JsonPropertyName("q")]
    public string? Q
    {
        get => this["q"];
        set => this["q"] = value;
    }
    [JsonPropertyName("g")]
    public string? G
    {
        get => this["g"];
        set => this["g"] = value;
    }
    [JsonPropertyName("y")]
    public string? Y
    {
        get => this["y"];
        set => this["y"] = value;
    }
}
