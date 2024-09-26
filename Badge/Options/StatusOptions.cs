using Net.Sdk.Web.Attributes;

namespace Badge.Options;

[OptionsName(Name = "Status")]
public sealed class StatusOptions
{
    public string? Version { get; set; } = Program.Version;
    public string? ApplicationName { get; set; } = Program.ApplicationName;
    public string? Environment { get; set; } = "Development";
}
