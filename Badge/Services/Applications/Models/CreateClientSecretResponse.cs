using Badge.Models;

namespace Badge.Services.Applications.Models;

public sealed class CreateClientSecretResponse(ClientSecret clientSecret, string password)
{
    public ClientSecret ClientSecret { get; } = clientSecret;
    public string Password { get; } = password;
}
