using Badge.Options;
using Badge.Services.Passwords.Versions;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Extensions.Core;

namespace Badge.Services.Passwords;

public sealed class PasswordService : IPasswordService
{
    private readonly Dictionary<PasswordServiceVersion, IPasswordServiceHashingAlgorithm> hashingAlgorithms = [];
    private readonly PasswordServiceOptions options;
    private readonly ILogger<PasswordService> logger;

    public PasswordService(
        IEnumerable<IPasswordServiceHashingAlgorithm> passwordServiceHashingAlgorithms,
        IOptions<PasswordServiceOptions> options,
        ILogger<PasswordService> logger)
    {
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
        foreach (var algorithm in passwordServiceHashingAlgorithms)
        {
            this.hashingAlgorithms[algorithm.Version] = algorithm;
        }
    }

    public async Task<string?> Hash(string password, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!this.hashingAlgorithms.TryGetValue(this.options.Version, out var hashingAlgorithm))
        {
            return default;
        }

        scopedLogger.LogDebug("Hashing password with {0}", hashingAlgorithm.Version);
        try
        {
            var hash = await hashingAlgorithm.Hash(password, cancellationToken);
            var versionBytes = BitConverter.GetBytes((int)hashingAlgorithm.Version);
            var mergedHash = new byte[versionBytes.Length + hash.Length];
            Buffer.BlockCopy(versionBytes, 0, mergedHash, 0, versionBytes.Length);
            Buffer.BlockCopy(hash, 0, mergedHash, versionBytes.Length, hash.Length);
            return Convert.ToBase64String(mergedHash);
        }
        catch(Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while hashing password");
            return default;
        }
    }

    public async Task<bool> Verify(string password, string hashedPassword, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        try
        {
            var mergedHash = Convert.FromBase64String(hashedPassword);
            var version = (PasswordServiceVersion)BitConverter.ToInt32(mergedHash, 0);
            if (!this.hashingAlgorithms.TryGetValue(version, out var hashingAlgorithm))
            {
                scopedLogger.LogError("Could not find hashing algorithm {0}", version);
                return false;
            }

            var result = await hashingAlgorithm.Verify(password, mergedHash.Skip(4).ToArray(), cancellationToken);
            return result;
        }
        catch(Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while verifying password");
            return false;
        }
    }
}
