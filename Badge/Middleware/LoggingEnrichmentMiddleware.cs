using Net.Sdk.Web;
using Serilog.Context;

namespace Badge.Middleware;

public sealed class LoggingEnrichmentMiddleware : IMiddleware
{
    public Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var ip = context.GetClientIP();
        var cv = context.GetCorrelationVector();
        LogContext.PushProperty("ClientIP", ip);
        LogContext.PushProperty("CorrelationVector", cv);
        return next(context);
    }
}
