using Badge.Middleware;
using Net.Sdk.Web.Middleware;
using System.Core.Extensions;

namespace Badge.Extensions;

public static class WebApplicationExtensions
{
    public static WebApplication RedirectEmptyPathToIndex(this WebApplication webApplication)
    {
        webApplication.ThrowIfNull()
        .Use(async (context, next) =>
        {
            if (context.Request.Path == "/")
            {
                context.Response.Redirect("/index");
                return;
            }

            await next();
        });

        return webApplication;
    }

    public static WebApplication UseWwwRoot(this WebApplication webApplication)
    {
        webApplication.ThrowIfNull()
            .UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProviderExtended(Path.Combine(Directory.GetCurrentDirectory(), "wwwroot")),
                ServeUnknownFileTypes = true,
                ContentTypeProvider = new StaticFilesContentTypeProvider(),
                RequestPath = ""
            });

        return webApplication;
    }

    public static WebApplication UseUserAuthentication(this WebApplication webApplication)
    {
        webApplication.ThrowIfNull().UseMiddleware<AuthenticationMiddleware>();
        return webApplication;
    }

    public static WebApplication UseLoggingEnrichment(this WebApplication webApplication)
    {
        webApplication.ThrowIfNull().UseMiddleware<LoggingEnrichmentMiddleware>();
        return webApplication;
    }

    public static WebApplication UseHeaderLogging(this WebApplication webApplication)
    {
        webApplication.ThrowIfNull().UseMiddleware<HeaderLoggingMiddleware>();
        return webApplication;
    }

    public static WebApplication UseHealthChecks(this WebApplication webApplication)
    {
        webApplication.ThrowIfNull().UseHealthChecks("/health");
        return webApplication;
    }
}
