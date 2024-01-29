using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Threading.Tasks;

namespace SecureWebhooks;

partial class Webhook
{
    public static Webhook Create<T>(string secret, T payload, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerSettings? options = null)
    {
        var payloadString = JsonConvert.SerializeObject(payload, options);
        return new(secret, payloadString, headerName);
    }

    public static async Task<Webhook<T>> FromAsync<T>(HttpRequest request, string secret, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerSettings? options = null)
    {
        var validationResult = await request.ValidateAndGetPayload(secret, headerName);
        return new(secret, validationResult, headerName, options);
    }
}

partial class Webhook<T>
{
    private readonly JsonSerializerSettings? _options;

    internal Webhook(string secret, ValidationResult validationResult, string headerName, JsonSerializerSettings? options)
        : this(secret, validationResult, headerName)
    {
        _options = options;
    }

    private T? Deserialize(string payload)
    {
        return JsonConvert.DeserializeObject<T>(payload, _options);
    }
}