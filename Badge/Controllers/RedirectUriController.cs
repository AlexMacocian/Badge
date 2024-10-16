using Badge.Filters;
using Badge.Models;
using Badge.Services.Applications;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using System.Core.Extensions;

namespace Badge.Controllers;

[GenerateController("api/applications/{applicationId}/redirect-uris")]
public sealed class RedirectUriController
{
    private readonly IApplicationService applicationService;

    public RedirectUriController(
        IApplicationService applicationService)
    {
        this.applicationService = applicationService.ThrowIfNull();
    }

    [GenerateGet]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> GetRedirectUris(AuthenticatedUser authenticatedUser, string applicationId, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, foundApplication =>
        {
            return Task.FromResult(Results.Json(foundApplication.Application.RedirectUris, SerializationContext.Default));
        }, cancellationToken);
    }

    [GeneratePost]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> PostRedirectUris(AuthenticatedUser authenticatedUser, string applicationId, [FromBody] List<string> redirectUris, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.UpdateRedirectUris(applicationId, redirectUris, cancellationToken) switch
            {
                Result<bool>.Success => Results.Ok(),
                Result<bool>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
                _ => Results.Problem(statusCode: 500)
            };
        }, cancellationToken);
    }

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
