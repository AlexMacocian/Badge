using System.Text.Json.Serialization;

namespace Badge.Models.JsonWebKeys;

public class RSAJsonWebKey : JsonWebKey
{
    [JsonPropertyName("n")]
    public string? Modulus
    {
        get => this["n"];
        set => this["n"] = value;
    }
    [JsonPropertyName("e")]
    public string? Exponent
    {
        get => this["e"];
        set => this["e"] = value;
    }
}
