using System.Core.Extensions;
using System.Diagnostics.CodeAnalysis;
using System.Extensions;

namespace Badge.Models.Identity;

public abstract class Identifier : IEquatable<Identifier>
{
    internal const char Separator = '-';

    public IdentifierTypeCode TypeCode { get; }
    public Guid UniqueId { get; }

    internal Identifier(IdentifierTypeCode typeCode, Guid uniqueId)
    {
        TypeCode = typeCode;
        UniqueId = uniqueId;
    }

    public bool Equals(Identifier? other)
    {
        if (other is null)
        {
            return false;
        }

        return TypeCode.Equals(other.TypeCode) && UniqueId.Equals(other.UniqueId);
    }

    public override bool Equals(object? obj)
    {
        if (obj is Identifier identifier)
        {
            return Equals(identifier);
        }

        return base.Equals(obj);
    }
    public override string ToString() => TypeCode.ToString() + Separator + UniqueId.ToString("N");
    public override int GetHashCode() => TypeCode.GetHashCode() ^ UniqueId.GetHashCode();

    public static bool operator ==(Identifier identifier1, Identifier identifier2)
    {
        return identifier1.Equals(identifier2);
    }

    public static bool operator !=(Identifier identifier1, Identifier identifier2)
    {
        return identifier1.Equals(identifier2) is false;
    }

    public static T Create<T>()
        where T : Identifier
    {
        var uid = Guid.NewGuid();
        var id = typeof(T) switch
        {
            Type t when t == typeof(UserIdentifier) => new UserIdentifier(uid) as T,
            Type t when t == typeof(ApplicationIdentifier) => new ApplicationIdentifier(uid) as T,
            Type t when t == typeof(ClientSecretIdentifier) => new ClientSecretIdentifier(uid) as T,
            Type t when t == typeof(KeyIdentifier) => new KeyIdentifier(uid) as T,
            _ => throw new InvalidOperationException($"Cannot create an identifier of type {typeof(T).Name}")
        };

        return id!;
    }
    public static Identifier ParseIdentifier(string? identifier)
    {
        identifier!.ThrowIfNull();
        if (TryParse(identifier, out var parsedIdentifier))
        {
            return parsedIdentifier!;
        }

        throw new InvalidOperationException($"Unable to parse identifier");
    }
    public static T ParseIdentifier<T>(string? identifier)
        where T : Identifier
    {
        var parsedIdentifier = ParseIdentifier(identifier);
        if (parsedIdentifier is not T typedParsedIdentifier)
        {
            throw new InvalidCastException($"Unable to cast {parsedIdentifier.GetType().Name} to {typeof(T).Name}");
        }

        return typedParsedIdentifier;
    }
    public static bool TryParse<T>(string? identifier, [NotNullWhen(true)] out T? parsedIdentifier)
        where T : Identifier
    {
        if (TryParse(identifier, out var parsedUntypedIdentifier) is false)
        {
            parsedIdentifier = null;
            return false;
        }

        if (parsedUntypedIdentifier is not T parsedTypedIdentifier)
        {
            parsedIdentifier = null;
            return false;
        }

        parsedIdentifier = parsedTypedIdentifier;
        return true;
    }
    public static bool TryParse(string? identifier, [NotNullWhen(true)] out Identifier? parsedIdentifier)
    {
        parsedIdentifier = default;
        if (identifier is null)
        {
            return false;
        }

        var tokens = identifier.Split(Separator);
        var typeCodeString = tokens.FirstOrDefault();
        if (int.TryParse(typeCodeString, out var typeCodeInt) is false ||
            typeCodeInt < 0 ||
            typeCodeInt > 99)
        {
            return false;
        }

        var uid = string.Concat(tokens.Skip(1));
        if (Guid.TryParse(uid, out var guid) is false)
        {
            return false;
        }

        var typeCode = new IdentifierTypeCode(typeCodeInt);
        if (typeCode.Equals(UserIdentifier.UserTypeCode))
        {
            parsedIdentifier = new UserIdentifier(guid);
            return true;
        }
        else if (typeCode.Equals(ApplicationIdentifier.ApplicationTypeCode))
        {
            parsedIdentifier = new ApplicationIdentifier(guid);
            return true;
        }
        else if (typeCode.Equals(ClientSecretIdentifier.ClientSecretTypeCode))
        {
            parsedIdentifier = new ClientSecretIdentifier(guid);
            return true;
        }
        else if (typeCode.Equals(KeyIdentifier.KeyTypeCode))
        {
            parsedIdentifier = new KeyIdentifier(guid);
            return true;
        }

        return false;
    }
}