using Microsoft.AspNetCore.Http;
using SecureWebhooks;
using System.Threading.Tasks;
using WH = SecureWebhooks.Webhook;

namespace Newtonsoft.Json.SecureWebhooks;

public static class Webhook
{
    public static WH Create<T>(string secret, T payload, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerSettings? options = null)
    {
        return WH.Create(secret, payload, x => JsonConvert.SerializeObject(x, options), headerName);
    }

    public static Task<Webhook<T>> FromAsync<T>(HttpRequest request, string secret, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerSettings? options = null)
    {
        return WH.FromAsync(request, secret, x => JsonConvert.DeserializeObject<T>(x, options)!, headerName);
    }
}