using Badge.Models.Identity;

namespace Badge.Models;

public sealed class User(UserIdentifier id, string username, string password)
{
    public UserIdentifier Id { get; set; } = id;
    public string Username { get; set; } = username;
    public string Password { get; set; } = password;
}
