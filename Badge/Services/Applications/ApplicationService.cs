using Badge.Models;
using Badge.Models.Identity;
using Badge.Options;
using Badge.Services.Applications.Models;
using Badge.Services.Database.Applications;
using Badge.Services.Passwords;
using Microsoft.Extensions.Options;
using System.Core.Extensions;
using System.Extensions.Core;
using System.Security.Cryptography;

namespace Badge.Services.Applications;

public sealed class ApplicationService : IApplicationService
{
    private readonly IPasswordService passwordService;
    private readonly IClientSecretDatabase clientSecretDatabase;
    private readonly IApplicationMembershipDatabase applicationOwnershipDatabase;
    private readonly IApplicationDatabase applicationDatabase;
    private readonly ApplicationOptions options;
    private readonly ILogger<ApplicationService> logger;

    public ApplicationService(
        IPasswordService passwordService,
        IClientSecretDatabase clientSecretDatabase,
        IApplicationMembershipDatabase applicationOwnershipDatabase,
        IApplicationDatabase applicationDatabase,
        IOptions<ApplicationOptions> options,
        ILogger<ApplicationService> logger)
    {
        this.passwordService = passwordService.ThrowIfNull();
        this.clientSecretDatabase = clientSecretDatabase.ThrowIfNull();
        this.applicationOwnershipDatabase = applicationOwnershipDatabase.ThrowIfNull();
        this.applicationDatabase = applicationDatabase.ThrowIfNull();
        this.options = options.ThrowIfNull().Value;
        this.logger = logger.ThrowIfNull();
    }

    public async Task<Result<bool>> AddOwner(string? applicationId, string? ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<ApplicationIdentifier>(applicationId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid application id");
        }

        if (!Identifier.TryParse<UserIdentifier>(ownerId, out var ownerIdentifier) ||
            ownerIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid owner id");
        }

        try
        {
            var result = await this.AssignOwnerInternal(applicationIdentifier, ownerIdentifier, cancellationToken);
            if (result)
            {
                return Result.Success(true);
            }

            return Result.Failure<bool>(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
        }

        return Result.Failure<bool>(500, "Unexpected error occurred");
    }

    public async Task<Result<bool>> RemoveOwner(string? applicationId, string? ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<ApplicationIdentifier>(applicationId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid application id");
        }

        if (!Identifier.TryParse<UserIdentifier>(ownerId, out var ownerIdentifier) ||
            ownerIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid owner id");
        }

        try
        {
            var result = await this.RemoveOwnerInternal(applicationIdentifier, ownerIdentifier, cancellationToken);
            if (result)
            {
                return Result.Success(true);
            }

            return Result.Failure<bool>(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while removing owner");
        }

        return Result.Failure<bool>(500, "Unexpected error occurred");
    }

    public async Task<Result<bool>> AddMember(string? applicationId, string? memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<ApplicationIdentifier>(applicationId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid application id");
        }

        if (!Identifier.TryParse<UserIdentifier>(memberId, out var memberIdentifier) ||
            memberIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid member id");
        }

        try
        {
            var result = await this.AssignMemberInternal(applicationIdentifier, memberIdentifier, cancellationToken);
            if (result)
            {
                return Result.Success(true);
            }

            return Result.Failure<bool>(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
        }

        return Result.Failure<bool>(500, "Unexpected error occurred");
    }

    public async Task<Result<bool>> RemoveMember(string? applicationId, string? memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<ApplicationIdentifier>(applicationId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid application id");
        }

        if (!Identifier.TryParse<UserIdentifier>(memberId, out var memberIdentifier) ||
            memberIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid member id");
        }

        try
        {
            var result = await this.RemoveMemberInternal(applicationIdentifier, memberIdentifier, cancellationToken);
            if (result)
            {
                return Result.Success(true);
            }

            return Result.Failure<bool>(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while removing owner");
        }

        return Result.Failure<bool>(500, "Unexpected error occurred");
    }

    public async Task<Result<Application>> CreateApplication(string? applicationName, string? ownerId, string? logo, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (string.IsNullOrWhiteSpace(applicationName))
        {
            return Result.Failure<Application>(400, "Invalid application name");
        }

        if (!Identifier.TryParse<UserIdentifier>(ownerId, out var ownerIdentifier) ||
            ownerIdentifier is null)
        {
            return Result.Failure<Application>(400, "Invalid owner id");
        }

        try
        {
            var application = await this.CreateApplicationInternal(applicationName, logo, cancellationToken);
            if (application is null)
            {
                scopedLogger.LogError("Failed to create application");
                return Result.Failure<Application>(500, "Failed to create application");
            }

            if (!await this.AssignOwnerInternal(application.Id, ownerIdentifier, cancellationToken))
            {
                scopedLogger.LogError("Failed to assign application owner");
                return Result.Failure<Application>(500, "Failed to assign ownerhip to new application");
            }

            return Result.Success(application);
        }
        catch(Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while creating application");
        }

        return Result.Failure<Application>(500, "Unexpected error occurred");
    }

    public async Task<Result<bool>> UpdateLogo(string? applicationId, string? logo, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<ApplicationIdentifier>(applicationId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid application id");
        }

        try
        {
            var result = await this.UpdateLogoInternal(applicationIdentifier, logo, cancellationToken);
            if (result)
            {
                return Result.Success(true);
            }

            return Result.Failure<bool>(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while updating logo");
        }

        return Result.Failure<bool>(500, "Unexpected error occurred");
    }

    public async Task<Result<List<Application>>> GetApplicationsByOwner(string? ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<UserIdentifier>(ownerId, out var ownerIdentifier) ||
            ownerIdentifier is null)
        {
            return Result.Failure<List<Application>>(400, "Invalid owner id");
        }

        try
        {
            var result = await this.GetApplicationsByOwnerInternal(ownerIdentifier, cancellationToken);
            if (result is not null)
            {
                return Result.Success(result);
            }

            return Result.Failure<List<Application>>(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
        }

        return Result.Failure<List<Application>>(500, "Unexpected error occurred");
    }

    public async Task<Result<List<ApplicationWithRights>>> GetApplicationsByMember(string? memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<UserIdentifier>(memberId, out var memberIdentifier) ||
            memberIdentifier is null)
        {
            return Result.Failure<List<ApplicationWithRights>>(400, "Invalid member id");
        }

        try
        {
            var result = await this.GetApplicationsByMemberInternal(memberIdentifier, cancellationToken);
            if (result is not null)
            {
                return Result.Success(result);
            }

            return Result.Failure<List<ApplicationWithRights>>(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
        }

        return Result.Failure<List<ApplicationWithRights>>(500, "Unexpected error occurred");
    }

    public async Task<Result<CreateClientSecretResponse>> CreateClientSecret(string? applicationId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<ApplicationIdentifier>(applicationId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<CreateClientSecretResponse>(400, "Invalid application id");
        }

        try
        {
            var clientSecret = await this.CreateClientSecretInternal(applicationIdentifier, cancellationToken);
            if (clientSecret is null)
            {
                return Result.Failure<CreateClientSecretResponse>(500, "Failed to create client secret");
            }

            return Result.Success(new CreateClientSecretResponse(clientSecret.Value.Item1, clientSecret.Value.Item2));
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while creating client secret");
            return Result.Failure<CreateClientSecretResponse>(500, "Failed to create client secret");
        }
    }

    public async Task<Result<List<ClientSecret>>> GetClientSecrets(string? applicationId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<ApplicationIdentifier>(applicationId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<List<ClientSecret>>(400, "Invalid application id");
        }

        try
        {
            var clientSecrets = await this.GetClientSecretsInternal(applicationIdentifier, cancellationToken);
            if (clientSecrets is null)
            {
                return Result.Failure<List<ClientSecret>>(500, "Failed to get client secrets");
            }

            return Result.Success(clientSecrets);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while retrieving client secrets");
            return Result.Failure<List<ClientSecret>>(500, "Failed to get client secrets");
        }
    }

    public async Task<Result<bool>> DeleteClientSecret(string? clientSecretId, string? ownerApplicationId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<ClientSecretIdentifier>(clientSecretId, out var clientSecretIdentifier) ||
            clientSecretIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid client secret id");
        }

        if (!Identifier.TryParse<ApplicationIdentifier>(ownerApplicationId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid application id");
        }

        try
        {
            var result = await this.DeleteClientSecretInternal(clientSecretIdentifier, applicationIdentifier, cancellationToken);
            if (result is false)
            {
                return Result.Failure<bool>(500, "Failed to delete client secret");
            }

            return Result.Success(true);
        }
        catch (Exception ex)
        {
            scopedLogger.LogError(ex, "Encountered exception while retrieving client secrets");
            return Result.Failure<bool>(500, "Failed to delete client secret");
        }
    }

    public async Task<Result<bool>> UpdateRedirectUris(string? applicationId, List<string>? redirectUris, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (!Identifier.TryParse<ApplicationIdentifier>(applicationId, out var applicationIdentifier) ||
            applicationIdentifier is null)
        {
            return Result.Failure<bool>(400, "Invalid application id");
        }

        if (redirectUris is null)
        {
            return Result.Failure<bool>(400, "Invalid redirect uris");
        }

        foreach(var redirectUri in redirectUris)
        {
            if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out var result))
            {
                return Result.Failure<bool>(400, $"{redirectUri} is not a valid URI");
            }

            if (result.Scheme.ToLower() is not "http" and not "https")
            {
                return Result.Failure<bool>(400, $"{redirectUri} has invalid scheme {result.Scheme}. Only 'http' or 'https' are allowed");
            }
        }

        try
        {
            var result = await this.UpdateRedirectUrisInternal(applicationIdentifier, redirectUris, cancellationToken);
            if (result)
            {
                return Result.Success(true);
            }

            return Result.Failure<bool>(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while updating logo");
        }

        return Result.Failure<bool>(500, "Unexpected error occurred");
    }

    private async Task<bool> DeleteClientSecretInternal(ClientSecretIdentifier clientSecretIdentifier, ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken)
    {
        return await this.clientSecretDatabase.RemoveClientSecret(clientSecretIdentifier, applicationIdentifier, cancellationToken);
    }

    private async Task<List<ClientSecret>?> GetClientSecretsInternal(ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken)
    {
        var clientSecrets = await this.clientSecretDatabase.GetClientSecrets(applicationIdentifier, cancellationToken);
        if (clientSecrets is null)
        {
            return default;
        }

        return clientSecrets.ToList();
    }

    private async Task<(ClientSecret, string)?> CreateClientSecretInternal(ApplicationIdentifier applicationIdentifier, CancellationToken cancellationToken)
    {
        var clientId = Identifier.Create<ClientSecretIdentifier>();
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(this.options.ClientSecretLength));
        var passwordHash = await this.passwordService.Hash(password, cancellationToken);
        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            return default;
        }

        var clientSecret = new ClientSecret(clientId, applicationIdentifier, DateTime.UtcNow, DateTime.UtcNow + this.options.ClientSecretValidity, passwordHash);
        if (!await this.clientSecretDatabase.StoreClientSecret(clientSecret, cancellationToken))
        {
            return default;
        }

        return (clientSecret, password);
    }

    private async Task<Application?> CreateApplicationInternal(string applicationName, string? logo, CancellationToken cancellationToken)
    {
        var applicationIdentifier = Identifier.Create<ApplicationIdentifier>();
        var application = new Application(applicationIdentifier, applicationName, logo ?? string.Empty, DateTime.UtcNow, []);
        var result = await this.applicationDatabase.CreateApplication(application, cancellationToken);
        if (!result)
        {
            return default;
        }

        return application;
    }

    private async Task<bool> UpdateLogoInternal(ApplicationIdentifier applicationId, string? logo, CancellationToken cancellationToken)
    {
        if (applicationId is null)
        {
            return false;
        }

        var result = await this.applicationDatabase.UpdateLogo(applicationId.ToString(), logo, cancellationToken);
        return result;
    }

    private async Task<bool> AssignOwnerInternal(ApplicationIdentifier applicationId, UserIdentifier ownerId, CancellationToken cancellationToken)
    {
        var result = await this.applicationOwnershipDatabase.AssignOwner(applicationId, ownerId, cancellationToken);
        return result;
    }

    private async Task<bool> RemoveOwnerInternal(ApplicationIdentifier applicationId, UserIdentifier ownerId, CancellationToken cancellationToken)
    {
        var result = await this.applicationOwnershipDatabase.RemoveOwner(applicationId, ownerId, cancellationToken);
        return result;
    }

    private async Task<bool> AssignMemberInternal(ApplicationIdentifier applicationId, UserIdentifier memberId, CancellationToken cancellationToken)
    {
        var result = await this.applicationOwnershipDatabase.AssignMember(applicationId, memberId, cancellationToken);
        return result;
    }

    private async Task<bool> RemoveMemberInternal(ApplicationIdentifier applicationId, UserIdentifier memberId, CancellationToken cancellationToken)
    {
        var result = await this.applicationOwnershipDatabase.RemoveMember(applicationId, memberId, cancellationToken);
        return result;
    }

    private async Task<List<Application>> GetApplicationsByOwnerInternal(UserIdentifier ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        var applicationList = new List<Application>();
        var applicationIds = await this.applicationOwnershipDatabase.GetOwnedApplications(ownerId, cancellationToken);
        foreach(var applicationId in applicationIds)
        {
            var application = await this.applicationDatabase.GetApplicationById(applicationId, cancellationToken);
            if (application is null)
            {
                scopedLogger.LogError($"Failed to find application by id: {applicationId}");
                continue;
            }

            applicationList.Add(application);
        }

        return applicationList;
    }

    private async Task<List<ApplicationWithRights>> GetApplicationsByMemberInternal(UserIdentifier memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        var applicationList = new List<ApplicationWithRights>();
        var applications = await this.applicationOwnershipDatabase.GetApplications(memberId, cancellationToken);
        foreach ((var applicationId, var owned) in applications)
        {
            var application = await this.applicationDatabase.GetApplicationById(applicationId, cancellationToken);
            if (application is null)
            {
                scopedLogger.LogError($"Failed to find application by id: {applicationId}");
                continue;
            }

            applicationList.Add(new ApplicationWithRights(application, owned));
        }

        return applicationList;
    }

    private async Task<bool> UpdateRedirectUrisInternal(ApplicationIdentifier applicationId, List<string> redirectUris, CancellationToken cancellationToken)
    {
        if (applicationId is null)
        {
            return false;
        }

        var result = await this.applicationDatabase.UpdateRedirectUris(applicationId.ToString(), redirectUris, cancellationToken);
        return result;
    }
}
