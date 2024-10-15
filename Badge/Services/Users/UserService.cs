using Badge.Models;
using Badge.Services.Database.Users;
using Badge.Services.JWT;
using Badge.Services.Passwords;
using System.Core.Extensions;
using System.Extensions.Core;

namespace Badge.Services.Users;

public sealed class UserService : IUserService
{
    private readonly IJWTService jWTService;
    private readonly IUserDatabase userDatabase;
    private readonly IPasswordService passwordService;
    private readonly ILogger<UserService> logger;

    public UserService(
        IJWTService jWTService,
        IUserDatabase userDatabase,
        IPasswordService passwordService,
        ILogger<UserService> logger)
    {
        this.jWTService = jWTService.ThrowIfNull();
        this.userDatabase = userDatabase.ThrowIfNull();
        this.passwordService = passwordService.ThrowIfNull();
        this.logger = logger.ThrowIfNull();
    }

    public async Task<JwtToken?> Login(string? username, string? password, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger(flowIdentifier: username ?? string.Empty);
        if (username is null)
        {
            scopedLogger.LogInformation("Username is null");
            return default;
        }

        if (password is null)
        {
            scopedLogger.LogInformation("Password is null");
            return default;
        }

        var user = await this.userDatabase.GetUser(username, cancellationToken);
        if (user is null)
        {
            scopedLogger.LogInformation("Could not find user");
            return default;
        }

        if (!await this.passwordService.Verify(password, user.Password, cancellationToken))
        {
            scopedLogger.LogInformation("Could not verify password");
            return default;
        }

        var jwtToken = await this.jWTService.GetLoginToken(username, cancellationToken);
        if (jwtToken is null)
        {
            scopedLogger.LogInformation("Could not create jwt token");
            return default;
        }

        return jwtToken;
    }

    public async Task<JwtToken?> CreateUser(string? username, string? password, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger(flowIdentifier: username ?? string.Empty);
        if (username is null)
        {
            scopedLogger.LogInformation("Username is null");
            return default;
        }

        if (password is null)
        {
            scopedLogger.LogInformation("Password is null");
            return default;
        }

        var hashedPassword = await this.passwordService.Hash(password, cancellationToken);
        if (hashedPassword is null)
        {
            scopedLogger.LogInformation("Failed to hash password");
            return default;
        }

        var user = await this.userDatabase.CreateUser(username, hashedPassword, cancellationToken);
        if (user is null)
        {
            scopedLogger.LogInformation("Could not create user");
            return default;
        }

        var jwtToken = await this.jWTService.GetLoginToken(username, cancellationToken);
        if (jwtToken is null)
        {
            scopedLogger.LogInformation("Could not create jwt token");
            return default;
        }

        return jwtToken;
    }

    public async Task<User?> GetUserByToken(string? token, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (token is null)
        {
            scopedLogger.LogInformation("Token is null");
            return default;
        }

        var claims = await this.jWTService.ValidateToken(token, cancellationToken);
        if (claims is null)
        {
            scopedLogger.LogInformation("Failed to validate token");
            return default;
        }

        var username = claims.Identity?.Name;
        if (username is null)
        {
            scopedLogger.LogError("No username in token");
            return default;
        }

        var user = await this.userDatabase.GetUser(username, cancellationToken);
        if (user is null)
        {
            scopedLogger.LogInformation("Could not find user");
            return default;
        }

        return user;
    }

    public async Task<User?> GetUserByUsername(string? username, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger(flowIdentifier: username ?? string.Empty);
        if (username is null)
        {
            scopedLogger.LogInformation("Username is null");
            return default;
        }

        var user = await this.userDatabase.GetUser(username, cancellationToken);
        if (user is null)
        {
            scopedLogger.LogInformation("Failed to find user");
            return default;
        }

        return user;
    }
}
