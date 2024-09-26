namespace Badge.Services.Passwords;

public interface IPasswordService
{
    Task<string?> Hash(string password, CancellationToken cancellationToken);
    Task<bool> Verify(string password, string hashedPassword, CancellationToken cancellationToken);
}
