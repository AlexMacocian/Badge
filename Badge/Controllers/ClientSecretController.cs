using Badge.Controllers.Models;
using Badge.Filters;
using Badge.Models;
using Badge.Services.Applications;
using Badge.Services.Applications.Models;
using Net.Sdk.Web;
using System.Core.Extensions;

namespace Badge.Controllers;

[GenerateController("api/applications/{applicationId}/secrets")]
public sealed class ClientSecretController
{
    private readonly IApplicationService applicationService;

    public ClientSecretController(
        IApplicationService applicationService)
    {
        this.applicationService = applicationService.ThrowIfNull();
    }

    [GenerateGet]
    [RouteFilter<AuthenticatedFilter>]
    public async Task<IResult> GetClientSecrets(string applicationId, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.GetClientSecrets(applicationId, cancellationToken) switch
            {
                Result<List<ClientSecret>>.Success clientSecrets => Results.Json(
                    clientSecrets.Result.Select(c => new ClientSecretResponse { Id = c.Id.ToString(), CreationDate = c.CreationDate, ExpirationDate = c.ExpirationDate }).ToList(), SerializationContext.Default),
                Result<List<ClientSecret>>.Failure clientSecretsFailure => Results.Problem(detail: clientSecretsFailure.ErrorMessage, statusCode: clientSecretsFailure.ErrorCode),
                _ => Results.Problem(statusCode: 500)
            };
        }, cancellationToken);
    }

    [GeneratePost]
    [RouteFilter<AuthenticatedFilter>]
    public async Task<IResult> CreateClientSecret(string applicationId, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.CreateClientSecret(applicationId, cancellationToken) switch
            {
                Result<CreateClientSecretResponse>.Success clientSecret =>
                    Results.Json(new ClientSecretResponseWithPassword
                    {
                        Id = clientSecret.Result.ClientSecret.Id.ToString(),
                        CreationDate = clientSecret.Result.ClientSecret.CreationDate,
                        ExpirationDate = clientSecret.Result.ClientSecret.ExpirationDate,
                        Password = clientSecret.Result.Password
                    }, SerializationContext.Default),
                Result<CreateClientSecretResponse>.Failure clientSecretsFailure => Results.Problem(detail: clientSecretsFailure.ErrorMessage, statusCode: clientSecretsFailure.ErrorCode),
                _ => Results.Problem(statusCode: 500)
            };
        }, cancellationToken);
    }

    [GenerateDelete("{clientSecretId}")]
    [RouteFilter<AuthenticatedFilter>]
    public async Task<IResult> DeleteClientSecret(string applicationId, AuthenticatedUser authenticatedUser, string clientSecretId, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.DeleteClientSecret(clientSecretId, applicationId, cancellationToken) switch
            {
                Result<bool>.Success => Results.Ok(),
                Result<bool>.Failure clientSecretsFailure => Results.Problem(detail: clientSecretsFailure.ErrorMessage, statusCode: clientSecretsFailure.ErrorCode),
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
