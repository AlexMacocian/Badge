using Badge.Controllers.Models;
using Badge.Filters;
using Badge.Models;
using Badge.Services.Applications;
using Badge.Services.Applications.Models;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using System.Core.Extensions;

namespace Badge.Controllers;

[GenerateController(Pattern = "api/applications")]
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

    [GenerateGet(Pattern = "me")]
    [RouteFilter(RouteFilterType = typeof(AuthenticatedFilter))]
    public async Task<IResult> GetApplications(AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id, cancellationToken);
        return result switch
        {
            ApplicationWithRightsListResponse.Success success => Results.Json(success.Applications, SerializationContext.Default),
            ApplicationWithRightsListResponse.Failure failure => Results.Problem(detail: failure.Error, statusCode: failure.StatusCode),
            _ => Results.Problem(statusCode: 500)
        };
    }

    [GenerateGet(Pattern = "{applicationId}")]
    [RouteFilter(RouteFilterType = typeof(AuthenticatedFilter))]
    public async Task<IResult> GetApplication(string applicationId, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id, cancellationToken);
        return result switch
        {
            ApplicationWithRightsListResponse.Success success => success.Applications.FirstOrDefault(app => app.Application.Id == applicationId) switch
            {
                ApplicationWithRights foundApplication => Results.Json(foundApplication.Application, SerializationContext.Default),
                _ => Results.NotFound()
            },
            ApplicationWithRightsListResponse.Failure failure => Results.Problem(detail: failure.Error, statusCode: failure.StatusCode),
            _ => Results.Problem(statusCode: 500)
        };
    }

    [GeneratePost(Pattern = "create")]
    [RouteFilter(RouteFilterType = typeof(AuthenticatedFilter))]
    public async Task<IResult> CreateApplication([FromBody] CreateApplicationRequest createApplicationRequest, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.CreateApplication(createApplicationRequest?.Name, authenticatedUser.User.Id, createApplicationRequest?.Base64Logo, cancellationToken);
        return result switch
        {
            ApplicationCreationResponse.Success success => Results.Created($"applications/{success.Application.Id}", success.Application),
            ApplicationCreationResponse.Failure failure => Results.Problem(detail: failure.Error, statusCode: failure.StatusCode),
            _ => Results.Problem(statusCode: 500)
        };
    }
}
