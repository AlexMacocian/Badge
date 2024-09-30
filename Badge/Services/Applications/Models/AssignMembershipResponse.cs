namespace Badge.Services.Applications.Models;

public abstract class AssignMembershipResponse
{
    public sealed class Success() : AssignMembershipResponse
    {
    }

    public sealed class Failure(int statusCode, string message) : AssignMembershipResponse
    {
        public int StatusCode { get; } = statusCode;
        public string Error { get; } = message;
    }
}
