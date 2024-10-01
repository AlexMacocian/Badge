namespace Badge.Services.Applications.Models;

public abstract class DeleteClientSecretResponse
{
    public sealed class Success() : DeleteClientSecretResponse
    {
    }

    public sealed class Failure(int statusCode, string message) : DeleteClientSecretResponse
    {
        public int StatusCode { get; } = statusCode;
        public string Error { get; } = message;
    }
}
