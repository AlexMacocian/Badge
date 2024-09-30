using Badge.Models;

namespace Badge.Services.Applications.Models;

public abstract class ApplicationListResponse
{
    public sealed class Success(List<Application> applications) : ApplicationListResponse
    {
        public List<Application> Applications { get; } = applications;
    }

    public sealed class Failure(int statusCode, string message) : ApplicationListResponse
    {
        public int StatusCode { get; } = statusCode;
        public string Error { get; } = message;
    }
}
