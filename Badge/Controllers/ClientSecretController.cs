using Badge.Controllers.Models;
using Badge.Filters;
using Badge.Models;
using Badge.Services.Applications;
using Badge.Services.Applications.Models;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using System.Core.Extensions;

namespace Badge.Controllers;

[GenerateController("api/applications/{applicationId}/secrets")]
public sealed class ClientSecretController(IApplicationService applicationService) : ApplicationControllerBase(applicationService)
{
    private readonly IApplicationService applicationService = applicationService.ThrowIfNull();

    [GenerateGet]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> GetClientSecrets(string applicationId, [FromServices] AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.GetClientSecrets(applicationId, cancellationToken) switch
            {
                Result<List<ClientSecret>>.Success clientSecrets => Results.Json(
                    clientSecrets.Result.Select(c => new ClientSecretResponse { Id = c.Id.ToString(), Detail = c.Detail, CreationDate = c.CreationDate, ExpirationDate = c.ExpirationDate }).ToList(), SerializationContext.Default),
                Result<List<ClientSecret>>.Failure clientSecretsFailure => Results.Problem(detail: clientSecretsFailure.ErrorMessage, statusCode: clientSecretsFailure.ErrorCode),
                _ => Results.Problem(statusCode: 500)
            };
        }, cancellationToken);
    }

    [GeneratePost]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> CreateClientSecret(string applicationId, [FromServices] AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.CreateClientSecret(applicationId, cancellationToken) switch
            {
                Result<CreateClientSecretResponse>.Success clientSecret =>
                    Results.Json(new ClientSecretResponseWithPassword
                    {
                        Id = clientSecret.Result.ClientSecret.Id.ToString(),
                        Detail = clientSecret.Result.ClientSecret.Detail,
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
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> DeleteClientSecret(string applicationId, [FromServices] AuthenticatedUser authenticatedUser, string clientSecretId, CancellationToken cancellationToken)
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

    [GeneratePost("{clientSecretId}/detail")]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> UpdateClientSecretDetail(string applicationId, [FromServices] AuthenticatedUser authenticatedUser, string clientSecretId, [FromBody]UpdateClientSecretDetailRequest? request, CancellationToken cancellationToken)
    {
        return await this.ExecuteIfApplicationOwned(applicationId, authenticatedUser, async foundApplication =>
        {
            return await this.applicationService.UpdateClientSecretDetail(applicationId, clientSecretId, request?.Detail, cancellationToken) switch
            {
                Result<bool>.Success => Results.Ok(),
                Result<bool>.Failure clientSecretsFailure => Results.Problem(detail: clientSecretsFailure.ErrorMessage, statusCode: clientSecretsFailure.ErrorCode),
                _ => Results.Problem(statusCode: 500)
            };
        }, cancellationToken);
    }
}
