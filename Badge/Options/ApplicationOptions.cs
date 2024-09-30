using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "Applications")]
public sealed class ApplicationOptions
{
    public ApplicationDatabaseOptions? ApplicationDatabase { get; set; }
    public ApplicationMembershipDatabaseOptions? MembershipDatabase { get; set; }
}
