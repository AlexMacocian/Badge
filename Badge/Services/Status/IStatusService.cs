using Badge.Models;

namespace Badge.Services.Status;

public interface IStatusService
{
    StatusResponse GetStatus();
}
