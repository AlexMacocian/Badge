using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public class UsernameWithPassword
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }
    [JsonPropertyName("password")]
    public string? Password { get; set; }
}
