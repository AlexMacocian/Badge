namespace Badge.Models.Identity;

public readonly struct IdentifierTypeCode : IEquatable<IdentifierTypeCode>
{
    public int Value { get; }

    public IdentifierTypeCode(int value)
    {
        if (value < 0 || value > 99)
        {
            throw new InvalidOperationException($"{nameof(IdentifierTypeCode)} can only have values between 0 and 99");
        }

        Value = value;
    }

    public override string ToString() => Value.ToString("00");

    public bool Equals(IdentifierTypeCode other) => Value == other.Value;

    public override int GetHashCode() => Value.GetHashCode();
    public override bool Equals(object? obj) => obj is IdentifierTypeCode code && Equals(code);
    public static bool operator ==(IdentifierTypeCode left, IdentifierTypeCode right)
    {
        return left.Equals(right);
    }
    public static bool operator !=(IdentifierTypeCode left, IdentifierTypeCode right)
    {
        return !(left == right);
    }
}