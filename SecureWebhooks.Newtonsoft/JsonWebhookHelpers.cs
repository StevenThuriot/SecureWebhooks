using Microsoft.AspNetCore.Http;
using SecureWebhooks;
using System.Net.Http;
using System.Threading.Tasks;

namespace Newtonsoft.Json.SecureWebhooks;

public static class JsonWebhookHelpers
{
    public static StringContent CreateContentWithSecureHeader<T>(string secret, T payload, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerSettings? options = null)
    {
        return WebhookHelpers.CreateContentWithSecureHeader(secret, payload, x => JsonConvert.SerializeObject(x, options), headerName);
    }

    public static Task<(bool isValid, T? payload)> ValidateAndGetPayload<T>(this HttpRequest request, string secret, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerSettings? options = null)
    {
        return request.ValidateAndGetPayload(secret, x => JsonConvert.DeserializeObject<T>(x, options), headerName);
    }
}
