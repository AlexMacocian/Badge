namespace Badge.Services.Applications.Models;

public abstract class RemoveMembershipResponse
{
    public sealed class Success() : RemoveMembershipResponse
    {
    }

    public sealed class Failure(int statusCode, string message) : RemoveMembershipResponse
    {
        public int StatusCode { get; } = statusCode;
        public string Error { get; } = message;
    }
}
