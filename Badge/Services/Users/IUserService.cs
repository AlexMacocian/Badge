using Badge.Models;

namespace Badge.Services.Users;

public interface IUserService
{
    Task<JwtToken?> Login(string? username, string? password, CancellationToken cancellationToken);
    Task<JwtToken?> CreateUser(string? username, string? password, CancellationToken cancellationToken);
    Task<User?> GetUserByUsername(string? username, CancellationToken cancellationToken);
    Task<User?> GetUserByToken(string? token, CancellationToken cancellationToken);
    Task<User?> GetUserById(string? id, CancellationToken cancellationToken);
}
