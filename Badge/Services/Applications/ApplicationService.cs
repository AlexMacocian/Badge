using Badge.Models;
using Badge.Services.Applications.Models;
using Badge.Services.Database.Applications;
using System.Core.Extensions;
using System.Extensions.Core;

namespace Badge.Services.Applications;

public sealed class ApplicationService : IApplicationService
{
    private readonly IApplicationMembershipDatabase applicationOwnershipDatabase;
    private readonly IApplicationDatabase applicationDatabase;
    private readonly ILogger<ApplicationService> logger;

    public ApplicationService(
        IApplicationMembershipDatabase applicationOwnershipDatabase,
        IApplicationDatabase applicationDatabase,
        ILogger<ApplicationService> logger)
    {
        this.applicationOwnershipDatabase = applicationOwnershipDatabase.ThrowIfNull();
        this.applicationDatabase = applicationDatabase.ThrowIfNull();
        this.logger = logger.ThrowIfNull();
    }

    public async Task<AssignMembershipResponse> AddOwner(string? applicationId, string? ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (string.IsNullOrWhiteSpace(applicationId))
        {
            return new AssignMembershipResponse.Failure(400, "Invalid application id");
        }

        if (string.IsNullOrWhiteSpace(ownerId))
        {
            return new AssignMembershipResponse.Failure(400, "Invalid owner id");
        }

        try
        {
            var result = await this.AssignOwnerInternal(applicationId, ownerId, cancellationToken);
            if (result)
            {
                return new AssignMembershipResponse.Success();
            }

            return new AssignMembershipResponse.Failure(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
        }

        return new AssignMembershipResponse.Failure(500, "Unexpected error occurred");
    }

    public async Task<RemoveMembershipResponse> RemoveOwner(string? applicationId, string? ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (string.IsNullOrWhiteSpace(applicationId))
        {
            return new RemoveMembershipResponse.Failure(400, "Invalid application id");
        }

        if (string.IsNullOrWhiteSpace(ownerId))
        {
            return new RemoveMembershipResponse.Failure(400, "Invalid owner id");
        }

        try
        {
            var result = await this.RemoveOwnerInternal(applicationId, ownerId, cancellationToken);
            if (result)
            {
                return new RemoveMembershipResponse.Success();
            }

            return new RemoveMembershipResponse.Failure(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while removing owner");
        }

        return new RemoveMembershipResponse.Failure(500, "Unexpected error occurred");
    }

    public async Task<AssignMembershipResponse> AddMember(string? applicationId, string? memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (string.IsNullOrWhiteSpace(applicationId))
        {
            return new AssignMembershipResponse.Failure(400, "Invalid application id");
        }

        if (string.IsNullOrWhiteSpace(memberId))
        {
            return new AssignMembershipResponse.Failure(400, "Invalid member id");
        }

        try
        {
            var result = await this.AssignMemberInternal(applicationId, memberId, cancellationToken);
            if (result)
            {
                return new AssignMembershipResponse.Success();
            }

            return new AssignMembershipResponse.Failure(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
        }

        return new AssignMembershipResponse.Failure(500, "Unexpected error occurred");
    }

    public async Task<RemoveMembershipResponse> RemoveMember(string? applicationId, string? memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (string.IsNullOrWhiteSpace(applicationId))
        {
            return new RemoveMembershipResponse.Failure(400, "Invalid application id");
        }

        if (string.IsNullOrWhiteSpace(memberId))
        {
            return new RemoveMembershipResponse.Failure(400, "Invalid member id");
        }

        try
        {
            var result = await this.RemoveMemberInternal(applicationId, memberId, cancellationToken);
            if (result)
            {
                return new RemoveMembershipResponse.Success();
            }

            return new RemoveMembershipResponse.Failure(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while removing owner");
        }

        return new RemoveMembershipResponse.Failure(500, "Unexpected error occurred");
    }

    public async Task<ApplicationCreationResponse> CreateApplication(string? applicationName, string? ownerId, string? logo, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (string.IsNullOrWhiteSpace(applicationName))
        {
            return new ApplicationCreationResponse.Failure(400, "Invalid application name");
        }

        if (string.IsNullOrWhiteSpace(ownerId))
        {
            return new ApplicationCreationResponse.Failure(400, "Invalid owner id");
        }

        try
        {
            var application = await this.CreateApplicationInternal(applicationName, logo, cancellationToken);
            if (application is null)
            {
                scopedLogger.LogError("Failed to create application");
                return new ApplicationCreationResponse.Failure(500, "Failed to create application");
            }

            if (!await this.AssignOwnerInternal(application.Id, ownerId, cancellationToken))
            {
                scopedLogger.LogError("Failed to assign application owner");
                return new ApplicationCreationResponse.Failure(500, "Failed to assign ownerhip to new application");
            }

            return new ApplicationCreationResponse.Success(application);
        }
        catch(Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while creating application");
        }

        return new ApplicationCreationResponse.Failure(500, "Unexpected error occurred");
    }

    public async Task<UpdateLogoResponse> UpdateLogo(string? applicationId, string? logo, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (string.IsNullOrWhiteSpace(applicationId))
        {
            return new UpdateLogoResponse.Failure(400, "Invalid application id");
        }

        try
        {
            var result = await this.UpdateLogoInternal(applicationId, logo, cancellationToken);
            if (result)
            {
                return new UpdateLogoResponse.Success();
            }

            return new UpdateLogoResponse.Failure(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while updating logo");
        }

        return new UpdateLogoResponse.Failure(500, "Unexpected error occurred");
    }

    public async Task<ApplicationListResponse> GetApplicationsByOwner(string? ownerId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (string.IsNullOrWhiteSpace(ownerId))
        {
            return new ApplicationListResponse.Failure(400, "Invalid owner id");
        }

        try
        {
            var result = await this.GetApplicationsByOwnerInternal(ownerId, cancellationToken);
            if (result is not null)
            {
                return new ApplicationListResponse.Success(result);
            }

            return new ApplicationListResponse.Failure(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
        }

        return new ApplicationListResponse.Failure(500, "Unexpected error occurred");
    }

    public async Task<ApplicationWithRightsListResponse> GetApplicationsByMember(string? memberId, CancellationToken cancellationToken)
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        if (string.IsNullOrWhiteSpace(memberId))
        {
            return new ApplicationWithRightsListResponse.Failure(400, "Invalid owner id");
        }

        try
        {
            var result = await this.GetApplicationsByMemberInternal(memberId, cancellationToken);
            if (result is not null)
            {
                return new ApplicationWithRightsListResponse.Success(result);
            }

            return new ApplicationWithRightsListResponse.Failure(500, "Unexpected error occurred");
        }
        catch (Exception e)
        {
            scopedLogger.LogError(e, "Encountered exception while assigning owner");
        }

        return new ApplicationWithRightsListResponse.Failure(500, "Unexpected error occurred");
    }

    private async Task<Application?> CreateApplicationInternal(string applicationName, string? logo, CancellationToken cancellationToken)
    {
        var application = new Application(Guid.NewGuid().ToString(), applicationName, logo ?? string.Empty, DateTime.Now);
        var result = await this.applicationDatabase.CreateApplication(application, cancellationToken);
        if (!result)
        {
            return default;
        }

        return application;
    }

    private async Task<bool> UpdateLogoInternal(string applicationId, string? logo, CancellationToken cancellationToken)
    {
        var result = await this.applicationDatabase.UpdateLogo(applicationId, logo, cancellationToken);
        return result;
    }

    private async Task<bool> AssignOwnerInternal(string applicationId, string ownerId, CancellationToken cancellationToken)
    {
        var result = await this.applicationOwnershipDatabase.AssignOwner(applicationId, ownerId, cancellationToken);
        return result;
    }

    private async Task<bool> RemoveOwnerInternal(string applicationId, string ownerId, CancellationToken cancellationToken)
    {
        var result = await this.applicationOwnershipDatabase.RemoveOwner(applicationId, ownerId, cancellationToken);
        return result;
    }

    private async Task<bool> AssignMemberInternal(string applicationId, string memberId, CancellationToken cancellationToken)
    {
        var result = await this.applicationOwnershipDatabase.AssignMember(applicationId, memberId, cancellationToken);
        return result;
    }

    private async Task<bool> RemoveMemberInternal(string applicationId, string memberId, CancellationToken cancellationToken)
    {
        var result = await this.applicationOwnershipDatabase.RemoveMember(applicationId, memberId, cancellationToken);
        return result;
    }

    private async Task<List<Application>> GetApplicationsByOwnerInternal(string ownerId, CancellationToken cancellationToken)
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

    private async Task<List<ApplicationWithRights>> GetApplicationsByMemberInternal(string memberId, CancellationToken cancellationToken)
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
}
