using Microsoft.AspNetCore.StaticFiles;
using System.Diagnostics.CodeAnalysis;
using System.Net.Mime;

namespace Badge.Extensions;

public class StaticFilesContentTypeProvider : IContentTypeProvider
{
    public bool TryGetContentType(string subpath, [MaybeNullWhen(false)] out string contentType)
    {
        var maybeExtension = Path.GetExtension(subpath);
        if (string.IsNullOrWhiteSpace(maybeExtension))
        {
            contentType = MediaTypeNames.Text.Html;
            return true;
        }

        switch (maybeExtension)
        {
            case ".html":
                contentType = MediaTypeNames.Text.Html;
                return true;
            case ".css":
                contentType = MediaTypeNames.Text.Css;
                return true;
            case ".json":
                contentType = MediaTypeNames.Application.Json;
                return true;
            case ".js":
                contentType = MediaTypeNames.Text.JavaScript;
                return true;
            default:
                contentType = MediaTypeNames.Text.Plain;
                return true;
        }
    }
}
