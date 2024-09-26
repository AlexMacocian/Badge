using Badge.Models;
using Badge.Options;
using Microsoft.Extensions.Options;
using System.Core.Extensions;

namespace Badge.Services.Status;

public sealed class StatusService : IStatusService
{
    private readonly StatusOptions options;

    public StatusService(
        IOptions<StatusOptions> options)
    {
        this.options = options.ThrowIfNull().Value;
    }

    public Task<StatusResponse> GetStatus()
    {
        return Task.FromResult(new StatusResponse
        { 
            Version = this.options.Version,
            Environment = this.options.Environment,
            ApplicationName = this.options.ApplicationName,
            StartedAt = Program.StartTime
        });
    }
}
