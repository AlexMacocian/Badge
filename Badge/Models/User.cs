namespace Badge.Models;

public sealed class User(string id, string username, string password)
{
    public string Id { get; set; } = id;
    public string Username { get; set; } = username;
    public string Password { get; set; } = password;
}
