using Badge.Controllers.Models;
using Badge.Filters;
using Badge.Models;
using Badge.Services.Applications;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using System.Core.Extensions;

namespace Badge.Controllers;

[GenerateController("api/applications")]
public sealed class ApplicationController
{
    private readonly IApplicationService applicationService;
    private readonly ILogger<ApplicationController> logger;

    public ApplicationController(
        IApplicationService applicationService,
        ILogger<ApplicationController> logger)
    {
        this.applicationService = applicationService.ThrowIfNull();
        this.logger = logger.ThrowIfNull();
    }

    [GenerateGet("me")]
    [RouteFilter<AuthenticatedFilter>]
    public async Task<IResult> GetApplications(AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id.ToString(), cancellationToken);
        return result switch
        {
            Result<List<ApplicationWithRights>>.Success success => Results.Json(success.Result.Select(a => new ApplicationResponse
            { 
                Id = a.Application.Id.ToString(),
                LogoBase64 = a.Application.LogoBase64,
                Scopes = a.Application.Scopes,
                Name = a.Application.Name,
                CreationDate = a.Application.CreationDate,
                Owned = a.Owned
            }).ToList(), SerializationContext.Default),
            Result<List<ApplicationWithRights>>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => Results.Problem(statusCode: 500)
        };
    }

    [GenerateGet("{applicationId}")]
    [RouteFilter<AuthenticatedFilter>]
    public async Task<IResult> GetApplication(string applicationId, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id.ToString(), cancellationToken);
        return result switch
        {
            Result<List<ApplicationWithRights>>.Success success => success.Result.FirstOrDefault(app => app.Application.Id.ToString() == applicationId) switch
            {
                ApplicationWithRights foundApplication => Results.Json(new ApplicationResponse
                {
                    Id = foundApplication.Application.Id.ToString(),
                    Name = foundApplication.Application.Name,
                    Scopes = foundApplication.Application.Scopes,
                    LogoBase64 = foundApplication.Application.LogoBase64,
                    CreationDate = foundApplication.Application.CreationDate,
                    Owned = foundApplication.Owned
                }, SerializationContext.Default),
                _ => Results.NotFound()
            },
            Result<List<ApplicationWithRights>>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => Results.Problem(statusCode: 500)
        };
    }

    [GeneratePost("create")]
    [RouteFilter<AuthenticatedFilter>]
    public async Task<IResult> CreateApplication([FromBody] CreateApplicationRequest createApplicationRequest, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.CreateApplication(createApplicationRequest?.Name, authenticatedUser.User.Id.ToString(), createApplicationRequest?.Base64Logo, cancellationToken);
        return result switch
        {
            Result<Application>.Success success => Results.Created($"applications/{success.Result.Id}",
                new ApplicationResponse
                { 
                    Id = success.Result.Id.ToString(),
                    Name = success.Result.Name,
                    CreationDate = success.Result.CreationDate,
                    LogoBase64 = success.Result.LogoBase64,
                    Owned = true
                }),
            Result<Application>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => Results.Problem(statusCode: 500)
        };
    }

    [GeneratePost("{applicationId}/scopes")]
    [RouteFilter<AuthenticatedFilter>]
    public async Task<IResult> UpdateApplicationScopes([FromBody] UpdateApplicationScopesRequest updateApplicationScopesRequest, AuthenticatedUser authenticatedUser, string applicationId, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.UpdateScopes(applicationId, updateApplicationScopesRequest.Scopes, cancellationToken) switch
            {
                Result<bool>.Success => Results.Ok(),
                Result<bool>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
                _ => Results.Problem(statusCode: 500)
            };
        }, cancellationToken);
    }

    // TODO: Application ownership logic should be moved to ApplicationService
    private async Task<IResult> ExecuteIfApplicationOwned(string applicationId, AuthenticatedUser authenticatedUser, Func<ApplicationWithRights, Task<IResult>> task, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id.ToString(), cancellationToken);
        return result switch
        {
            Result<List<ApplicationWithRights>>.Success success => success.Result.FirstOrDefault(app => app.Application.Id.ToString() == applicationId) switch
            {
                ApplicationWithRights foundApplication => await task(foundApplication),
                _ => Results.NotFound()
            },
            Result<List<ApplicationWithRights>>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => Results.Problem(statusCode: 500)
        };
    }
}
