using Badge.Filters;
using Badge.Models;
using Badge.Services.Applications;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using System.Core.Extensions;

namespace Badge.Controllers;

[GenerateController("api/applications/{applicationId}/redirect-uris")]
public sealed class RedirectUriController(IApplicationService applicationService) : ApplicationControllerBase(applicationService)
{
    private readonly IApplicationService applicationService = applicationService.ThrowIfNull();

    [GenerateGet]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> GetRedirectUris([FromServices] AuthenticatedUser authenticatedUser, string applicationId, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, foundApplication =>
        {
            return Results.Json(foundApplication.Application.RedirectUris, SerializationContext.Default);
        }, cancellationToken);
    }

    [GeneratePost]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> PostRedirectUris([FromServices] AuthenticatedUser authenticatedUser, string applicationId, [FromBody] List<string> redirectUris, CancellationToken cancellationToken)
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
}
