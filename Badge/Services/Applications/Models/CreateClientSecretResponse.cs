using Badge.Models;

namespace Badge.Services.Applications.Models;

public abstract class CreateClientSecretResponse
{
    public sealed class Success(ClientSecret clientSecret, string password) : CreateClientSecretResponse
    {
        public ClientSecret ClientSecret { get; } = clientSecret;
        public string Password { get; } = password;
    }

    public sealed class Failure(int statusCode, string message) : CreateClientSecretResponse
    {
        public int StatusCode { get; } = statusCode;
        public string Error { get; } = message;
    }
}
