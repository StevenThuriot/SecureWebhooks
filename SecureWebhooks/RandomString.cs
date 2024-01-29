using System;
using System.Security.Cryptography;

namespace SecureWebhooks;

public sealed class RandomString
{
    public const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string Lower = "abcdefghijklmnopqrstuvwxyz";
    public const string Digits = "0123456789";
    public const string Alphanum = Upper + Lower + Digits;

    private readonly string _value;

    public RandomString(int length, string symbols)
    {
#if NETSTANDARD2_0
        var ratio = uint.MaxValue / (double)symbols.Length;
        var buffer = new char[length];

        for (int i = 0; i < length; ++i)
        {
            int randomIndex = GetInt32();
            buffer[i] = symbols[randomIndex];
        }

        _value = new string(buffer);

        int GetInt32()
        {
            using var generator = RandomNumberGenerator.Create();

            var bytes = new byte[4];
            generator.GetBytes(bytes);

            return (int)(BitConverter.ToUInt32(bytes, 0) / ratio);
        }
#else
        Span<char> buffer = stackalloc char[length];

        for (int i = 0; i < length; ++i)
        {
            int randomIndex = RandomNumberGenerator.GetInt32(symbols.Length);
            buffer[i] = symbols[randomIndex];
        }

        _value = new string(buffer);
#endif
    }

    public RandomString(int length)
        : this(length, Alphanum)
    {
    }

    public RandomString()
        : this(128)
    {
    }

    public override string ToString()
    {
        return _value;
    }

    public static implicit operator string(RandomString value)
    {
        return value.ToString();
    }
}