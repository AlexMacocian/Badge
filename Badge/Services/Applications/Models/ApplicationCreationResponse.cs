using Badge.Models;

namespace Badge.Services.Applications.Models;

public abstract class ApplicationCreationResponse
{
    public sealed class Success(Application application) : ApplicationCreationResponse
    {
        public Application Application { get; } = application;
    }

    public sealed class Failure(int statusCode, string message) : ApplicationCreationResponse
    {
        public int StatusCode { get; } = statusCode;
        public string Error { get; } = message;
    }
}
