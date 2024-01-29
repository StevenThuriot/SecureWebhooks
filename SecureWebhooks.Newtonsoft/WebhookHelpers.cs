using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Net.Http;
using System.Threading.Tasks;

namespace SecureWebhooks;

static partial class WebhookHelpers
{
    public static StringContent CreateContentWithSecureHeader<T>(string secret, T payload, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerSettings? options = null)
    {
        var payloadString = JsonConvert.SerializeObject(payload, options);
        return CreateContentWithSecureHeader(secret, payloadString, headerName);
    }

    public static async Task<ValidationResult<T>> ValidateAndGetPayload<T>(this HttpRequest request, string secret, string headerName = SecureWebhookConstants.HookSignatureHeader, JsonSerializerSettings? options = null)
    {
        var validationResult = await request.ValidateAndGetPayload(secret, headerName);

        return !validationResult
                ? default(ValidationResult<T>)
                : JsonConvert.DeserializeObject<T>(validationResult.Payload!, options);
    }
}
