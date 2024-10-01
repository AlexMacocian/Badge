using Badge.Models.Identity;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Badge.Converters;

public class IdentifierConverter : JsonConverter<Identifier>
{
    public override Identifier? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var stringValue = reader.GetString();
        if (string.IsNullOrWhiteSpace(stringValue))
        {
            return null;
        }

        return Identifier.ParseIdentifier(stringValue);
    }

    public override void Write(Utf8JsonWriter writer, Identifier value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}
