using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;

namespace Badge.Converters;

public class HashAlgorithmNameTypeConverter : TypeConverter
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
            "md5" => HashAlgorithmName.MD5,
            "sha1" => HashAlgorithmName.SHA1,
            "sha256" => HashAlgorithmName.SHA256,
            "sha384" => HashAlgorithmName.SHA384,
            "sha512" => HashAlgorithmName.SHA512,
            "sha3_256" => HashAlgorithmName.SHA3_256,
            "sha3_384" => HashAlgorithmName.SHA3_384,
            "sha3_512" => HashAlgorithmName.SHA3_512,
            _ => throw new InvalidOperationException($"Unable to parse {valueString}")
        };
    }
}

