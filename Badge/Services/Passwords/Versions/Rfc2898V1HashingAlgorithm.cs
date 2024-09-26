using System.Security.Cryptography;

namespace Badge.Services.Passwords.Versions;

public sealed class Rfc2898V1HashingAlgorithm : IPasswordServiceHashingAlgorithm
{
    private const int SaltSize = 16;      // 128-bit salt
    private const int KeySize = 32;       // 256-bit key
    private const int Iterations = 10000;
    private static readonly HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA512;

    public PasswordServiceVersion Version => PasswordServiceVersion.V1;

    public Task<byte[]> Hash(string password, CancellationToken cancellationToken)
    {
        return Task.Run(() => HashPasswordInternal(password), cancellationToken);
    }

    public Task<bool> Verify(string password, byte[] storedHash, CancellationToken cancellationToken)
    {
        return Task.Run(() => VerifyInternal(password, storedHash), cancellationToken);
    }

    private static byte[] HashPasswordInternal(string password)
    {
        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[SaltSize];
        rng.GetBytes(salt);

        using var deriveBytes = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithm);
        var hash = deriveBytes.GetBytes(KeySize);
        var hashBytes = new byte[SaltSize + KeySize];
        Buffer.BlockCopy(salt, 0, hashBytes, 0, SaltSize);
        Buffer.BlockCopy(hash, 0, hashBytes, SaltSize, KeySize);

        return hashBytes;
    }

    private static bool VerifyInternal(string password, byte[] storedHash)
    {
        var salt = new byte[SaltSize];
        Buffer.BlockCopy(storedHash, 0, salt, 0, SaltSize);

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithm);
        var hash = pbkdf2.GetBytes(KeySize);
        for (int i = 0; i < KeySize; i++)
        {
            if (storedHash[i + SaltSize] != hash[i])
            {
                return false;
            }
        }

        return true;
    }
}
