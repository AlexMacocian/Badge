using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "Users")]
public sealed class UserServiceOptions
{
    public TimeSpan TokenDuration { get; set; }
}
