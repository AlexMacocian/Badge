namespace Badge.Extensions;

public static class HttpContextExtensions
{
    private const string UsernameKey = "Username";

    public static string? GetUsername(this HttpContext context)
    {
        if (context.Items.TryGetValue(UsernameKey, out var username) &&
            username is string usernameStr)
        {
            return usernameStr;
        }

        return default;
    }

    public static void SetUsername(this HttpContext context, string username)
    {
        context.Items.Add(UsernameKey, username);
    }
}
