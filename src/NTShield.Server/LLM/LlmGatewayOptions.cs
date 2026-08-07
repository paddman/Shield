namespace NTShield.Server.LLM;

public sealed class LlmGatewayOptions
{
    public const string SectionName = "LLMGateway";

    /// <summary>Enable the token gateway and OpenAI-compatible proxy.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>OpenAI-compatible upstream base URL, normally ending in /v1.</summary>
    public string BaseUrl { get; set; } = "http://127.0.0.1:8000/v1";

    /// <summary>Server-side upstream key. Never returned by the management API.</summary>
    public string ApiKey { get; set; } = "";

    /// <summary>Optional default model shown in the Control Center.</summary>
    public string Model { get; set; } = "";

    /// <summary>Accept a self-signed upstream certificate for controlled testing only.</summary>
    public bool SkipTlsVerify { get; set; }

    public int TimeoutSeconds { get; set; } = 120;
    public int DefaultTokenLifetimeDays { get; set; } = 90;
    public int MaxTokenLifetimeDays { get; set; } = 3650;
}
