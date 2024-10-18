using Badge.Services.Status;
using Net.Sdk.Web;
using System.Core.Extensions;
using System.Extensions.Core;

namespace Badge.Controllers;

[GenerateController("api/status")]
public sealed class StatusController
{
    private readonly IStatusService statusService;
    private readonly ILogger<StatusController> logger;

    public StatusController(
        IStatusService statusService,
        ILogger<StatusController> logger)
    {
        this.statusService = statusService.ThrowIfNull();
        this.logger = logger.ThrowIfNull();
    }

    [GenerateGet]
    public IResult GetStatus()
    {
        var scopedLogger = this.logger.CreateScopedLogger();
        scopedLogger.LogDebug("Received status request");
        var status = this.statusService.GetStatus();
        return Results.Json(status, SerializationContext.Default);
    }
}
