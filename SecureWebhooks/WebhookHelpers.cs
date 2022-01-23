using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureWebhooks;

public static class WebhookHelpers
{
    private const string HookSignatureHeader = "X-Hook-Signature-256";
    private const string SignaturePrefix = "sha256=";

    public static StringContent CreateContentWithSecureHeader<T>(string secret, T payload, Func<T, string> serialize, string headerName = HookSignatureHeader)
    {
        var payloadString = serialize(payload);
        return CreateContentWithSecureHeader(secret, payloadString, headerName);
    }

    private static StringContent CreateContentWithSecureHeader(string secret, string payload, string headerName = HookSignatureHeader)
    {
        var content = new StringContent(payload, Encoding.UTF8, "application/json");
        content.AddSecureHeader(secret, payload, headerName);
        return content;
    }

    public static void AddSecureHeader(this HttpContent content, string secret, string payload, string headerName = HookSignatureHeader)
    {
        content.Headers.AddSecureHeader(secret, payload, headerName);
    }

    public static void AddSecureHeader(this HttpContentHeaders headers, string secret, string payload, string headerName = HookSignatureHeader)
    {
        byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
        headers.Add(headerName, CreateHeaderValue(secret, payloadBytes));
    }

    public static async Task<(bool isValid, T? payload)> ValidateAndGetPayload<T>(this HttpRequest request, string secret, Func<string, T> deserialize, string headerName = HookSignatureHeader)
    {
        var (isValid, payload) = await request.ValidateAndGetPayload(secret, headerName);

        return !isValid
                ? (false, default)
                : (true, deserialize(payload!));
    }

    public static async Task<(bool isValid, string? payload)> ValidateAndGetPayload(this HttpRequest request, string secret, string headerName = HookSignatureHeader)
    {
        if (!request.Headers.TryGetValue(headerName, out var values))
        {
            return (false, default);
        }

        var signature = values.ToString();
        if (signature?.StartsWith(SignaturePrefix, StringComparison.OrdinalIgnoreCase) != true)
        {
            return (false, default);
        }

        using var ms = new MemoryStream();
        await request.Body.CopyToAsync(ms);

        var payload = ms.ToArray();

        var validationSignature = CreateHeaderValue(secret, payload);

        if (!StringComparer.OrdinalIgnoreCase.Equals(signature, validationSignature))
        {
            return (false, default);
        }

        return (true, Encoding.UTF8.GetString(payload));
    }

    private static string CreateHeaderValue(string secret, byte[] payload)
    {
        return SignaturePrefix + CalculateSignature(secret, payload);
    }

    private static string CalculateSignature(string secret, byte[] payloadBytes)
    {
        byte[] secretBytes = Encoding.ASCII.GetBytes(secret);
        using var sha = new HMACSHA256(secretBytes);

        byte[] hash = sha.ComputeHash(payloadBytes);

#if !NETSTANDARD
        return Convert.ToHexString(hash);
#elif NETSTANDARD2_1_OR_GREATER
        var bytes = new ReadOnlySpan<byte>(hash);

        const uint casing = 0u; // Casing.Upper; 
        // Lower = 8224u

        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                return string.Create(bytes.Length * 2, ((IntPtr)ptr, bytes.Length), (Span<char> chars, (IntPtr Ptr, int Length) args) =>
                {
                    ReadOnlySpan<byte> bytes2 = new ReadOnlySpan<byte>((void*)args.Ptr, args.Length);

                    for (int i = 0; i < bytes2.Length; i++)
                    {
                        byte value = bytes2[i];

                        uint num = (uint)(((value & 0xF0) << 4) + (value & 0xF) - 35209);
                        uint num2 = ((((0 - num) & 0x7070) >> 4) + num + 47545) | casing;

                        int startingIndex = i * 2;
                        chars[startingIndex + 1] = (char)(num2 & 0xFFu);
                        chars[startingIndex] = (char)(num2 >> 8);
                    }
                });
            }
        }
#else
        var builder = new StringBuilder(hash.Length * 2);

        for (int i = 0; i < hash.Length; i++)
        {
            builder.AppendFormat("{0:X2}", hash[i]);
        }

        return builder.ToString();
#endif
    }
}