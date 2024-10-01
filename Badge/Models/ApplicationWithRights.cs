namespace Badge.Models;

public sealed class ApplicationWithRights(Application application, bool owned)
{
    public Application Application { get; } = application;
    public bool Owned { get; } = owned;
}
