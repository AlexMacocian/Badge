using Badge.Models;
using Badge.Services.Applications;
using Microsoft.AspNetCore.Mvc;
using System.Core.Extensions;

namespace Badge.Controllers;

public abstract class ApplicationControllerBase
{
    private readonly IApplicationService applicationService;

    public ApplicationControllerBase(IApplicationService applicationService)
    {
        this.applicationService = applicationService.ThrowIfNull();
    }

    protected async Task<IResult> ExecuteIfApplicationOwned(string applicationId, [FromServices] AuthenticatedUser authenticatedUser, Func<ApplicationWithRights, Task<IResult>> task, CancellationToken cancellationToken)
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

    protected async Task<IResult> ExecuteIfApplicationOwned(string applicationId, [FromServices] AuthenticatedUser authenticatedUser, Func<ApplicationWithRights, IResult> task, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id.ToString(), cancellationToken);
        return result switch
        {
            Result<List<ApplicationWithRights>>.Success success => success.Result.FirstOrDefault(app => app.Application.Id.ToString() == applicationId) switch
            {
                ApplicationWithRights foundApplication => task(foundApplication),
                _ => Results.NotFound()
            },
            Result<List<ApplicationWithRights>>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => Results.Problem(statusCode: 500)
        };
    }
}
