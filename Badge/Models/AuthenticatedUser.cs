namespace Badge.Models;

public sealed class AuthenticatedUser(User user)
{
    public User User { get; } = user;
}
