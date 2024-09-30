using System.Text.Json.Serialization;

namespace Badge.Models;

public sealed class ApplicationWithRights(Application application, bool owned)
{
    [JsonPropertyName("application")]
    public Application Application { get; } = application;
    [JsonPropertyName("owned")]
    public bool Owned { get; } = owned;
}
