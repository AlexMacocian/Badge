using Badge.Models;

namespace Badge.Services.Database.Users;

public interface IUserDatabase
{
    Task<User?> GetUser(string username, CancellationToken cancellationToken);
    Task<User?> CreateUser(string username, string password, CancellationToken cancellationToken);
}
