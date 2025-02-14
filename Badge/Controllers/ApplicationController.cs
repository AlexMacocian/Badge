﻿using Badge.Controllers.Models;
using Badge.Filters;
using Badge.Models;
using Badge.Services.Applications;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using System.Core.Extensions;

namespace Badge.Controllers;

[GenerateController("api/applications")]
public sealed class ApplicationController(IApplicationService applicationService) : ApplicationControllerBase(applicationService)
{
    private readonly IApplicationService applicationService = applicationService.ThrowIfNull();

    [GenerateGet("me")]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> GetApplications([FromServices] AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
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

    [GenerateGet("{applicationId}/info")]
    public async Task<IResult> GetApplicationInfo(string applicationId, CancellationToken cancellationToken)
    {
        var result = await this.applicationService.GetApplicationDetails(applicationId, cancellationToken);
        return result switch
        {
            Result<ApplicationDetails>.Success success => Results.Json(new ApplicationDetailsResponse
            {
                Id = success.Result.Id.ToString(),
                LogoBase64 = success.Result.LogoBase64,
                Name = success.Result.Name
            }, SerializationContext.Default),
            Result<ApplicationDetails>.Failure failure => Results.Problem(detail: failure.ErrorMessage, statusCode: failure.ErrorCode),
            _ => Results.Problem(statusCode: 500)
        };
    }

    [GenerateGet("{applicationId}")]
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> GetApplication(string applicationId, [FromServices] AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
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
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> CreateApplication([FromBody] CreateApplicationRequest createApplicationRequest, [FromServices] AuthenticatedUser authenticatedUser, CancellationToken cancellationToken)
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
    [RouteFilter<LoginAuthenticatedFilter>]
    public async Task<IResult> UpdateApplicationScopes([FromBody] UpdateApplicationScopesRequest updateApplicationScopesRequest, [FromServices] AuthenticatedUser authenticatedUser, string applicationId, CancellationToken cancellationToken)
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
}
