using System.Text.Json.Serialization;

namespace Badge.Controllers.Models;

public class UserDetails
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }
}
