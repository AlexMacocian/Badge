namespace Badge.Services.Passwords.Versions;

public interface IPasswordServiceHashingAlgorithm
{
    PasswordServiceVersion Version { get; }
    public Task<byte[]> Hash(string password, CancellationToken cancellationToken);
    public Task<bool> Verify(string password, byte[] storedHash, CancellationToken cancellationToken);
}
