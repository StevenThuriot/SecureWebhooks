using Microsoft.AspNetCore.Http;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Tasks;

namespace SecureWebhooks;

static partial class WebhookHelpers
{
    public static StringContent CreateContentWithSecureHeader<T>(string secret, T payload, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerOptions? options = null)
    {
        var payloadString = JsonSerializer.Serialize(payload, options);
        return CreateContentWithSecureHeader(secret, payloadString, headerName);
    }

    public static async Task<ValidationResult<T>> ValidateAndGetPayload<T>(this HttpRequest request, string secret, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerOptions? options = null)
    {
        var validationResult = await request.ValidateAndGetPayload(secret, headerName);

        return !validationResult
                ? default(ValidationResult<T>)
                : JsonSerializer.Deserialize<T>(validationResult.Payload!, options);
    }

    public static StringContent CreateContentWithSecureHeader<T>(string secret, T payload, JsonTypeInfo<T> typeInfo, string headerName = SecureWebhookConstants.HookSignatureHeader)
    {
        var payloadString = JsonSerializer.Serialize(payload, typeInfo);
        return CreateContentWithSecureHeader(secret, payloadString, headerName);
    }

    public static async Task<ValidationResult<T>> ValidateAndGetPayload<T>(this HttpRequest request, string secret, JsonTypeInfo<T> typeInfo, string headerName = SecureWebhookConstants.HookSignatureHeader)
    {
        var validationResult = await request.ValidateAndGetPayload(secret, headerName);

        return !validationResult
                ? default(ValidationResult<T>)
                : JsonSerializer.Deserialize(validationResult.Payload!, typeInfo);
    }
}
