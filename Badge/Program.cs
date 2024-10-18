using Badge.Controllers;
using Badge.Controllers.Models;
using Badge.Extensions;
using Badge.Filters;
using Badge.Models;
using Microsoft.AspNetCore.Mvc;
using Net.Sdk.Web;
using Net.Sdk.Web.Websockets.Extensions;
using System.Runtime.CompilerServices;

namespace Badge
{
    public class Program
    {
        public const string Version = "0.1.0";
        public const string ApplicationName = "Badge";
        public static readonly DateTime StartTime = DateTime.Now;

        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateSlimBuilder(args);

            builder
                .WithRoutes()
                .WithAntiforgery()
                .WithSerializationContext()
                .WithSQLiteDatabase()
                .WithUserServices()
                .WithApplicationServices()
                .WithHttpContextAccessor()
                .WithFormattedLogging()
                .WithCorrelation()
                .WithIPExtraction()
                .WithLoggingEnrichment()
                .WithHealthChecks()
                .WithJWTServices()
                .WithCertificateServices()
                .WithPasswordServices()
                .WithAuthorize()
                .WithStatus();

            var app = builder.Build()
                .UseCorrelationVector()
                .UseIPExtraction()
                .UseLoggingEnrichment()
                .RedirectEmptyPathToIndex()
                .UseWwwRoot()
                .UseAntiforgeryMiddleware()
                .UseUserAuthentication()
                .UseHealthChecks();
                //.UseRoutes(); //This call doesn't work. When built with NativeAOT, some of the mappings don't await but instead they return and try to serialize Task<IResult>

            UseRoutes2(app); //This is a copy of UseRoutes and placed below. This works for some reason and the mapping always await and never try to serialize Task<IResult>
            app.Run();
        }

        // Identical copy of UseRoutes
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization | MethodImplOptions.PreserveSig)]
        public static WebApplication UseRoutes2(WebApplication builder)
        {
            builder.MapPost("/api/users/login", (HttpContext httpContext, UsersController route, [FromBody] UsernameWithPassword payload) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.Login(payload, httpContext, cancellationToken);
            });
            builder.MapPost("/api/users/create", (HttpContext httpContext, UsersController route, [FromBody] UsernameWithPassword payload) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.Create(payload, httpContext, cancellationToken);
            });
            builder.MapGet("/api/users/me", (HttpContext httpContext, UsersController route, [FromServices] AuthenticatedUser authenticatedUser) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.Me(authenticatedUser);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapGet("/api/applications/{applicationId}/redirect-uris/", (HttpContext httpContext, RedirectUriController route, [FromServices] AuthenticatedUser authenticatedUser, string applicationId) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetRedirectUris(authenticatedUser, applicationId, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapPost("/api/applications/{applicationId}/redirect-uris/", (HttpContext httpContext, RedirectUriController route, [FromServices] AuthenticatedUser authenticatedUser, string applicationId, [FromBody] List<string> redirectUris) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.PostRedirectUris(authenticatedUser, applicationId, redirectUris, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapGet("/api/applications/{applicationId}/secrets/", (HttpContext httpContext, ClientSecretController route, string applicationId, [FromServices] AuthenticatedUser authenticatedUser) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetClientSecrets(applicationId, authenticatedUser, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapPost("/api/applications/{applicationId}/secrets/", (HttpContext httpContext, ClientSecretController route, string applicationId, [FromServices] AuthenticatedUser authenticatedUser) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.CreateClientSecret(applicationId, authenticatedUser, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapDelete("/api/applications/{applicationId}/secrets/{clientSecretId}", (HttpContext httpContext, ClientSecretController route, string applicationId, [FromServices] AuthenticatedUser authenticatedUser, string clientSecretId) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.DeleteClientSecret(applicationId, authenticatedUser, clientSecretId, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapPost("/api/applications/{applicationId}/secrets/{clientSecretId}/detail", (HttpContext httpContext, ClientSecretController route, string applicationId, [FromServices] AuthenticatedUser authenticatedUser, string clientSecretId, [FromBody] UpdateClientSecretDetailRequest? request) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.UpdateClientSecretDetail(applicationId, authenticatedUser, clientSecretId, request, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapGet("/api/applications/me", (HttpContext httpContext, ApplicationController route, [FromServices] AuthenticatedUser authenticatedUser) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetApplications(authenticatedUser, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapGet("/api/applications/{applicationId}/info", (HttpContext httpContext, ApplicationController route, string applicationId) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetApplicationInfo(applicationId, cancellationToken);
            });
            builder.MapGet("/api/applications/{applicationId}", (HttpContext httpContext, ApplicationController route, string applicationId, [FromServices] AuthenticatedUser authenticatedUser) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetApplication(applicationId, authenticatedUser, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapPost("/api/applications/create", (HttpContext httpContext, ApplicationController route, [FromBody] CreateApplicationRequest createApplicationRequest, [FromServices] AuthenticatedUser authenticatedUser) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.CreateApplication(createApplicationRequest, authenticatedUser, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapPost("/api/applications/{applicationId}/scopes", (HttpContext httpContext, ApplicationController route, [FromBody] UpdateApplicationScopesRequest updateApplicationScopesRequest, [FromServices] AuthenticatedUser authenticatedUser, string applicationId) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.UpdateApplicationScopes(updateApplicationScopesRequest, authenticatedUser, applicationId, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            builder.MapGet("/api/status/", (HttpContext httpContext, StatusController route) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetStatus();
            });
            builder.MapGet("/api/oauth/.well-known/openid-configuration", (HttpContext httpContext, OAuthController route) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetDiscoveryDocument();
            });
            builder.MapGet("/api/oauth/.well-known/jwks.json", (HttpContext httpContext, OAuthController route) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetJwks(cancellationToken);
            });
            builder.MapGet("/api/oauth/userinfo", (HttpContext httpContext, OAuthController route) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetUserInfo(httpContext, cancellationToken);
            })
            .AddEndpointFilter<AccessTokenAuthenticatedFilter>();
            builder.MapPost("/api/oauth/token", (HttpContext httpContext, OAuthController route) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetOAuthToken(httpContext, cancellationToken);
            });
            builder.MapGet("/api/oauth/scopes", (HttpContext httpContext, OAuthController route) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.GetOauthScopes();
            });
            builder.MapPost("/api/oauth/authorize", (HttpContext httpContext, OAuthController route, [FromServices] AuthenticatedUser authenticatedUser, [FromBody] AuthorizeRequest request) =>
            {
                var cancellationToken = httpContext.RequestAborted;
                return route.Authorize(authenticatedUser, request, cancellationToken);
            })
            .AddEndpointFilter<LoginAuthenticatedFilter>();
            return builder;
        }
    }
}
