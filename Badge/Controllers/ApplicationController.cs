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
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id.ToString(), cancellationToken);
        return result switch
        {
            ApplicationWithRightsListResponse.Success success => Results.Json(success.Applications.Select(a => new ApplicationResponse
            { 
                Id = a.Application.Id.ToString(),
                LogoBase64 = a.Application.LogoBase64,
                Name = a.Application.Name,
                CreationDate = a.Application.CreationDate,
                Owned = a.Owned
            }).ToList(), SerializationContext.Default),
            ApplicationWithRightsListResponse.Failure failure => Results.Problem(detail: failure.Error, statusCode: failure.StatusCode),
            _ => Results.Problem(statusCode: 500)
        };
    }

    [GenerateGet(Pattern = "{applicationId}")]
    [RouteFilter(RouteFilterType = typeof(AuthenticatedFilter))]
    public async Task<IResult> GetApplication(string applicationId, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id.ToString(), cancellationToken);
        return result switch
        {
            ApplicationWithRightsListResponse.Success success => success.Applications.FirstOrDefault(app => app.Application.Id.ToString() == applicationId) switch
            {
                ApplicationWithRights foundApplication => Results.Json(new ApplicationResponse
                {
                    Id = foundApplication.Application.Id.ToString(),
                    Name = foundApplication.Application.Name,
                    LogoBase64 = foundApplication.Application.LogoBase64,
                    CreationDate = foundApplication.Application.CreationDate,
                    Owned = foundApplication.Owned
                }, SerializationContext.Default),
                _ => Results.NotFound()
            },
            ApplicationWithRightsListResponse.Failure failure => Results.Problem(detail: failure.Error, statusCode: failure.StatusCode),
            _ => Results.Problem(statusCode: 500)
        };
    }

    [GenerateGet(Pattern = "{applicationId}/secrets")]
    [RouteFilter(RouteFilterType = typeof(AuthenticatedFilter))]
    public async Task<IResult> GetApplicationClientSecrets(string applicationId, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id.ToString(), cancellationToken);
        return result switch
        {
            ApplicationWithRightsListResponse.Success success => success.Applications.FirstOrDefault(app => app.Application.Id.ToString() == applicationId) switch
            {
                ApplicationWithRights foundApplication => await this.applicationService.GetClientSecrets(applicationId, cancellationToken) switch
                {
                    GetClientSecretsResponse.Success clientSecrets => Results.Json(
                        clientSecrets.ClientSecrets.Select(c => new ClientSecretResponse { Id = c.Id.ToString(), CreationDate = c.CreationDate, ExpirationDate = c.ExpirationDate }).ToList(), SerializationContext.Default),
                    GetClientSecretsResponse.Failure clientSecretsFailure => Results.Problem(detail: clientSecretsFailure.Error, statusCode: clientSecretsFailure.StatusCode),
                    _ => Results.Problem(statusCode: 500)
                },
                _ => Results.NotFound()
            },
            ApplicationWithRightsListResponse.Failure failure => Results.Problem(detail: failure.Error, statusCode: failure.StatusCode),
            _ => Results.Problem(statusCode: 500)
        };
    }

    [GeneratePost(Pattern = "{applicationId}/secrets")]
    [RouteFilter(RouteFilterType = typeof(AuthenticatedFilter))]
    public async Task<IResult> CreateApplicationClientSecret(string applicationId, AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationsByMember(authenticatedUser.User.Id.ToString(), cancellationToken);
        return result switch
        {
            ApplicationWithRightsListResponse.Success success => success.Applications.FirstOrDefault(app => app.Application.Id.ToString() == applicationId) switch
            {
                ApplicationWithRights foundApplication => await this.applicationService.CreateClientSecret(applicationId, cancellationToken) switch
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
                },
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
        var result = await this.applicationService.CreateApplication(createApplicationRequest?.Name, authenticatedUser.User.Id.ToString(), createApplicationRequest?.Base64Logo, cancellationToken);
        return result switch
        {
            ApplicationCreationResponse.Success success => Results.Created($"applications/{success.Application.Id}",
                new ApplicationResponse
                { 
                    Id = success.Application.Id.ToString(),
                    Name = success.Application.Name,
                    CreationDate = success.Application.CreationDate,
                    LogoBase64 = success.Application.LogoBase64,
                    Owned = true
                }),
            ApplicationCreationResponse.Failure failure => Results.Problem(detail: failure.Error, statusCode: failure.StatusCode),
            _ => Results.Problem(statusCode: 500)
        };
    }
}
