using Badge.Services.Passwords.Versions;
using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "PasswordService")]
public class PasswordServiceOptions
{
    public PasswordServiceVersion Version { get; set; }
}
