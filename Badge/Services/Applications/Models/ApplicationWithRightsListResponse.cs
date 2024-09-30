using Badge.Models;

namespace Badge.Services.Applications.Models;

public abstract class ApplicationWithRightsListResponse
{
    public sealed class Success(List<ApplicationWithRights> applications) : ApplicationWithRightsListResponse
    {
        public List<ApplicationWithRights> Applications { get; } = applications;
    }

    public sealed class Failure(int statusCode, string message) : ApplicationWithRightsListResponse
    {
        public int StatusCode { get; } = statusCode;
        public string Error { get; } = message;
    }
}
