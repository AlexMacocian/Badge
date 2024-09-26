using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;

namespace Badge.Converters;

public class RSASignaturePaddingTypeConverter : TypeConverter
{
    public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType)
    {
        return sourceType == typeof(string) || base.CanConvertFrom(context, sourceType);
    }

    public override object ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object? value)
    {
        if (value is not string valueString)
        {
            throw new InvalidOperationException($"Unable to convert from {value?.GetType()}");
        }

        return valueString.ToLower() switch
        {
            "pkcs1" => RSASignaturePadding.Pkcs1,
            "pss" => RSASignaturePadding.Pss,
            _ => throw new InvalidOperationException($"Unable to parse {valueString}")
        };
    }
}

