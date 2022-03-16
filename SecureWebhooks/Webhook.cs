using Microsoft.AspNetCore.Http;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace SecureWebhooks;

public class Webhook
{
    protected readonly string _secret;
    protected readonly string _payload;
    protected readonly string _headerName;

    private (string name, string value) _event;

    protected Webhook(string secret, string payload, string headerName)
    {
        _secret = secret;
        _payload = payload;
        _headerName = headerName;
    }

    public Webhook WithEvent(string @event, string headerName = SecureWebhookConstants.HookSignatureHeader)
    {
        if (_event != default)
        {
            throw new NotSupportedException("Event has already been set");
        }

        _event = (headerName, @event);

        return this;
    }

    public static Webhook Create<T>(string secret, T payload, Func<T, string> serialize, string headerName = SecureWebhookConstants.HookSignatureHeader)
    {
        var payloadString = serialize(payload);
        return new(secret, payloadString, headerName);
    }

    public static async Task<Webhook<T>> FromAsync<T>(HttpRequest request, string secret, Func<string, T> deserialize, string headerName = SecureWebhookConstants.HookSignatureHeader)
    {
        var (isValid, payload) = await request.ValidateAndGetPayload(secret, headerName);
        return new Webhook<T>(secret, payload, isValid, deserialize, headerName);
    }

    public static implicit operator HttpContent(Webhook webhook)
    {
        var content = WebhookHelpers.CreateContentWithSecureHeader(secret: webhook._secret, payload: webhook._payload, headerName: webhook._headerName);

        if (webhook._event != default)
        {
            content.Headers.Add(webhook._event.name, webhook._event.value);
        }

        return content;
    }
}

public class Webhook<T> : Webhook
{
    private readonly Func<string, T> _deserialize;

    public bool IsValid { get; }

    internal Webhook(string secret, string? payload, bool isValid, Func<string, T> deserialize, string headerName)
        : base (secret, payload ?? "", headerName)
    {
        IsValid = isValid;
        _deserialize = deserialize;
    }

    public T ToObject()
    {
        if (TryGetObject(out var result))
        {
            return result!;
        }

        throw new InvalidOperationException("The payload is not valid");
    }

    public bool TryGetObject(out T? value)
    {
        if (!IsValid)
        {
            value = default;
            return false;
        }

        try
        {
            value = _deserialize(_payload);
            return true;
        }
        catch
        {
            value = default;
            return false;
        }
    }

    public static implicit operator T(Webhook<T> webhook) => webhook.ToObject();
}