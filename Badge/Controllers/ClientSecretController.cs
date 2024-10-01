using Badge.Controllers.Models;
using Badge.Filters;
using Badge.Models;
using Badge.Services.Applications;
using Badge.Services.Applications.Models;
using Net.Sdk.Web;
using System.Core.Extensions;

namespace Badge.Controllers;

[GenerateController(Pattern = "api/applications/{applicationId}/secrets")]
public sealed class ClientSecretController
{
    private readonly IApplicationService applicationService;

    public ClientSecretController(
        IApplicationService applicationService)
    {
        this.applicationService = applicationService.ThrowIfNull();
    }

    [GenerateGet]
    [RouteFilter(RouteFilterType = typeof(AuthenticatedFilter))]
    public async Task<IResult> GetClientSecrets(string applicationId, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.GetClientSecrets(applicationId, cancellationToken) switch
            {
                GetClientSecretsResponse.Success clientSecrets => Results.Json(
                    clientSecrets.ClientSecrets.Select(c => new ClientSecretResponse { Id = c.Id.ToString(), CreationDate = c.CreationDate, ExpirationDate = c.ExpirationDate }).ToList(), SerializationContext.Default),
                GetClientSecretsResponse.Failure clientSecretsFailure => Results.Problem(detail: clientSecretsFailure.Error, statusCode: clientSecretsFailure.StatusCode),
                _ => Results.Problem(statusCode: 500)
            };
        }, cancellationToken);
    }

    [GeneratePost]
    [RouteFilter(RouteFilterType = typeof(AuthenticatedFilter))]
    public async Task<IResult> CreateClientSecret(string applicationId, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.CreateClientSecret(applicationId, cancellationToken) switch
            {
                CreateClientSecretResponse.Success clientSecret =>
                    Results.Json(new ClientSecretResponseWithPassword
                    {
                        Id = clientSecret.ClientSecret.Id.ToString(),
                        CreationDate = clientSecret.ClientSecret.CreationDate,
                        ExpirationDate = clientSecret.ClientSecret.ExpirationDate,
                        Password = clientSecret.Password
                    }, SerializationContext.Default),
                CreateClientSecretResponse.Failure clientSecretsFailure => Results.Problem(detail: clientSecretsFailure.Error, statusCode: clientSecretsFailure.StatusCode),
                _ => Results.Problem(statusCode: 500)
            };
        }, cancellationToken);
    }

    [GenerateDelete(Pattern = "{clientSecretId}")]
    [RouteFilter(RouteFilterType = typeof(AuthenticatedFilter))]
    public async Task<IResult> DeleteClientSecret(string applicationId, AuthenticatedUser authenticatedUser, string clientSecretId, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.DeleteClientSecret(clientSecretId, applicationId, cancellationToken) switch
            {
                DeleteClientSecretResponse.Success => Results.Ok(),
                DeleteClientSecretResponse.Failure clientSecretsFailure => Results.Problem(detail: clientSecretsFailure.Error, statusCode: clientSecretsFailure.StatusCode),
                _ => Results.Problem(statusCode: 500)
            };
        }, cancellationToken);
    }

    private async Task<IResult> ExecuteIfApplicationOwned(string applicationId, AuthenticatedUser authenticatedUser, Func<ApplicationWithRights, Task<IResult>> task, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id.ToString(), cancellationToken);
        return result switch
        {
            ApplicationWithRightsListResponse.Success success => success.Applications.FirstOrDefault(app => app.Application.Id.ToString() == applicationId) switch
            {
                ApplicationWithRights foundApplication => await task(foundApplication),
                _ => Results.NotFound()
            },
            ApplicationWithRightsListResponse.Failure failure => Results.Problem(detail: failure.Error, statusCode: failure.StatusCode),
            _ => Results.Problem(statusCode: 500)
        };
    }
}
