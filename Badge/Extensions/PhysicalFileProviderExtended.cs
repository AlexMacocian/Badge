using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.FileProviders.Physical;
using Microsoft.Extensions.Primitives;

namespace Badge.Extensions;

public sealed class PhysicalFileProviderExtended : IFileProvider, IDisposable
{
    private readonly PhysicalFileProvider physicalFileProvider;

    public PhysicalFileProviderExtended(string root)
    {
        this.physicalFileProvider = new PhysicalFileProvider(root);
    }

    public PhysicalFileProviderExtended(string root, ExclusionFilters filters)
    {
        this.physicalFileProvider = new PhysicalFileProvider(root, filters);
    }

    public void Dispose()
    {
        this.physicalFileProvider.Dispose();
    }

    public IDirectoryContents GetDirectoryContents(string subpath)
    {
        return this.physicalFileProvider.GetDirectoryContents(subpath);
    }

    public IFileInfo GetFileInfo(string subpath)
    {
        var fileInfo = this.physicalFileProvider.GetFileInfo(subpath);
        if (fileInfo.Exists)
        {
            return fileInfo;
        }

        var fileInfo2 = this.physicalFileProvider.GetFileInfo($"{subpath}.html");
        if (fileInfo2.Exists)
        {
            return fileInfo2;
        }

        return fileInfo;
    }

    public IChangeToken Watch(string filter)
    {
        return this.physicalFileProvider.Watch(filter);
    }
}
