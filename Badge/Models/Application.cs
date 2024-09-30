using System.Text.Json.Serialization;

namespace Badge.Models;

public sealed class Application(string id, string name, string logoBase64, DateTime creationDate)
{
    [JsonPropertyName("id")]
    public string Id { get; } = id;
    [JsonPropertyName("name")]
    public string Name { get; } = name;
    [JsonPropertyName("logoBase64")]
    public string LogoBase64 { get; } = logoBase64;
    [JsonPropertyName("creationDate")]
    public DateTime CreationDate { get; } = creationDate;
}
