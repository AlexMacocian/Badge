using System.Text.Json.Serialization;

namespace Badge.Models;

public sealed class User(string id, string username, string password)
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = id;
    [JsonPropertyName("username")]
    public string Username { get; set; } = username;
    [JsonPropertyName("password")]
    public string Password { get; set; } = password;
}
