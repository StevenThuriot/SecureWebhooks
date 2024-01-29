using System;
using System.Net.Http;

namespace SecureWebhooks;

public partial class Webhook
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

public sealed partial class Webhook<T> : Webhook
{
    public bool IsValid { get; }

    private Webhook(string secret, ValidationResult validationResult, string headerName)
        : base(secret, validationResult.Payload ?? "", headerName)
    {
        IsValid = validationResult;
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
            value = Deserialize(_payload);
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