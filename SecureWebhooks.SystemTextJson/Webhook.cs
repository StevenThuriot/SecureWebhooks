using Microsoft.AspNetCore.Http;
using SecureWebhooks;
using System.Threading.Tasks;
using WH = SecureWebhooks.Webhook;

namespace System.Text.Json.SecureWebhooks;

public static class Webhook
{
    public static WH Create<T>(string secret, T payload, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerOptions? options = null)
    {
        return WH.Create(secret, payload, x => JsonSerializer.Serialize(x, options), headerName);
    }

    public static Task<Webhook<T>> FromAsync<T>(HttpRequest request, string secret, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerOptions? options = null)
    {
        return WH.FromAsync(request, secret, x => JsonSerializer.Deserialize<T>(x, options)!, headerName);
    }
}