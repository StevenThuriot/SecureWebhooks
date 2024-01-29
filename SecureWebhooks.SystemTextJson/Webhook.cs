using Microsoft.AspNetCore.Http;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Tasks;

namespace SecureWebhooks;

partial class Webhook
{
    public static Webhook Create<T>(string secret, T payload, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerOptions? options = null)
    {
        var payloadString = JsonSerializer.Serialize(payload, options);
        return new(secret, payloadString, headerName);
    }

    public static async Task<Webhook<T>> FromAsync<T>(HttpRequest request, string secret, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerOptions? options = null)
    {
        var validationResult = await request.ValidateAndGetPayload(secret, headerName);
        return new(secret, validationResult, headerName, options);
    }

    public static async Task<Webhook<T>> FromAsync<T>(HttpRequest request, string secret, JsonTypeInfo<T> typeInfo, string headerName = SecureWebhookConstants.HookSignatureHeader)
    {
        var validationResult = await request.ValidateAndGetPayload(secret, headerName);
        return new(secret, validationResult, headerName, typeInfo);
    }
}

partial class Webhook<T>
{
    private readonly JsonSerializerOptions? _options;

    private readonly JsonTypeInfo<T>? _typeInfo;

    internal Webhook(string secret, ValidationResult validationResult, string headerName, JsonSerializerOptions? options)
        : this(secret,validationResult, headerName)
    {
        _options = options;
    }

    internal Webhook(string secret, ValidationResult validationResult, string headerName, JsonTypeInfo<T> typeInfo)
        : this(secret, validationResult, headerName)
    {
        _typeInfo = typeInfo;
    }

    private T? Deserialize(string payload)
    {
        if (_typeInfo is not null)
        {
            return JsonSerializer.Deserialize(payload, _typeInfo);
        }

        return JsonSerializer.Deserialize<T>(payload, _options);
    }
}