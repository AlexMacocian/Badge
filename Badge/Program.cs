using Badge.Controllers;
using Badge.Extensions;
using Badge.Options;
using Microsoft.Extensions.Options;
using Net.Sdk.Web;
using Net.Sdk.Web.Options;
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
                .UseHealthChecks()
                .UseRoutes();

            app.MapPost("/test", async (HttpContext context, OAuthController route) =>
            {
                var cancellationToken = context.RequestAborted;
                return await route.GetToken(context, cancellationToken);
            });

            app.Run();
        }

        private static async Task<IResult> SomeResult()
        {
            await Task.Delay(100);
            return Results.Ok("Hello world");
        }
    }
}
