using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;

namespace Badge.Converters;

public class Base64ToX509Certificate2TypeConverter : TypeConverter
{
    public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType)
    {
        return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
    }

    public override object ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object? value)
    {
        if (value is string base64String)
        {
            byte[] certData = Convert.FromBase64String(base64String);
            return new X509Certificate2(certData, string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }

        throw new InvalidOperationException($"Unable to convert from {value?.GetType()}");
    }
}

