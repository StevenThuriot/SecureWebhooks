namespace SecureWebhooks;

public static class SecureWebhookConstants
{
    public const string HookSignatureHeader = "X-Hook-Signature-256";
    public const string SignaturePrefix = "sha256=";
}
