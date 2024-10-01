using Badge.Models;

namespace Badge.Services.Applications.Models;

public abstract class GetClientSecretsResponse
{
    public sealed class Success(List<ClientSecret> clientSecrets) : GetClientSecretsResponse
    {
        public List<ClientSecret> ClientSecrets { get; } = clientSecrets;
    }

    public sealed class Failure(int statusCode, string message) : GetClientSecretsResponse
    {
        public int StatusCode { get; } = statusCode;
        public string Error { get; } = message;
    }
}
