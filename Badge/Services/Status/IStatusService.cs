using Badge.Models;

namespace Badge.Services.Status;

public interface IStatusService
{
    Task<StatusResponse> GetStatus();
}
