namespace NTShield.Server.Syslog;

public sealed class SyslogOptions
{
    public const string SectionName = "Syslog";

    /// <summary>Enable UDP syslog listener on Central.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>UDP port (5514 avoids needing elevated bind on 514).</summary>
    public int UdpPort { get; set; } = 5514;

    /// <summary>Optional TCP syslog (0 = disabled).</summary>
    public int TcpPort { get; set; } = 0;

    /// <summary>Path to open-source signature pack JSON.</summary>
    public string SignaturesPath { get; set; } =
        @"C:\ProgramData\NTShield\Server\signatures\opensource-signatures.json";

    public bool MatchOpenSourceSignatures { get; set; } = true;
}
