using Badge.Models;
using Badge.Models.Identity;

namespace Badge.Services.Database.Users;

public interface IUserDatabase
{
    Task<User?> GetUser(string username, CancellationToken cancellationToken);
    Task<User?> GetUser(UserIdentifier userIdentifier, CancellationToken cancellationToken);
    Task<User?> CreateUser(string username, string password, CancellationToken cancellationToken);
}
