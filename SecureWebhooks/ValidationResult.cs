global using ValidationResult = SecureWebhooks.ValidationResult<string>;

namespace SecureWebhooks;

#if NET6_0_OR_GREATER
public readonly record struct ValidationResult<T>(bool IsValid, T? Payload)
{
#else
public readonly struct ValidationResult<T>(bool isValid, T? payload)
{
    public readonly bool IsValid = isValid;
    public readonly T? Payload = payload;
#endif
    public static implicit operator bool(ValidationResult<T> validationResult) => validationResult.IsValid;
    public static implicit operator ValidationResult<T>(T? body) => new(body is not null, body);
};