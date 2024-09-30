namespace Badge.Services.Applications.Models;

public abstract class UpdateLogoResponse
{
    public sealed class Success() : UpdateLogoResponse
    {
    }

    public sealed class Failure(int statusCode, string message) : UpdateLogoResponse
    {
        public int StatusCode { get; } = statusCode;
        public string Error { get; } = message;
    }
}
