using Microsoft.AspNetCore.Http;
using SecureWebhooks;
using System.Net.Http;
using System.Threading.Tasks;

namespace System.Text.Json.SecureWebhooks;

public static class JsonWebhookHelpers
{
    public static StringContent CreateContentWithSecureHeader<T>(string secret, T payload, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerOptions? options = null)
    {
        return WebhookHelpers.CreateContentWithSecureHeader(secret, payload, x => JsonSerializer.Serialize(x, options), headerName);
    }

    public static Task<(bool isValid, T? payload)> ValidateAndGetPayload<T>(this HttpRequest request, string secret, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerOptions? options = null)
    {
        return request.ValidateAndGetPayload(secret, x => JsonSerializer.Deserialize<T>(x, options), headerName);
    }
}
