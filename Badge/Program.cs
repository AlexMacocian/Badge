using Badge.Extensions;
using Net.Sdk.Web;
using Net.Sdk.Web.Options;
using Net.Sdk.Web.Websockets.Extensions;

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
                .WithAppSettings()
                .WithSerializationContext()
                .WithSQLiteDatabase()
                .WithUserServices()
                .WithHttpContextAccessor()
                .WithFormattedLogging()
                .WithCorrelationVector()
                .ConfigureExtended<CorrelationVectorOptions>()
                .WithIPExtraction()
                .WithLoggingEnrichment()
                .WithHealthChecks()
                .WithJWTServices()
                .WithCertificateServices()
                .WithPasswordServices()
                .WithAuthorize()
                .WithStatus();

            var app = builder.Build()
                .RedirectEmptyPathToIndex()
                .UseWwwRoot()
                .UseCorrelationVector()
                .UseIPExtraction()
                .UseLoggingEnrichment()
                .UseHealthChecks()
                .UseRoutes();

            app.Run();
        }
    }
}
