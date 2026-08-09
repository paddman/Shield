namespace NTShield.Server.Data;

public sealed class ClickHouseOptions
{
    public const string SectionName = "ClickHouse";

    /// <summary>ClickHouse HTTP/native connection string used by the official .NET driver.</summary>
    public string ConnectionString { get; set; } = "Host=127.0.0.1;Port=8123;Database=default";

    /// <summary>Database that receives NT Shield analytics events.</summary>
    public string Database { get; set; } = "ntshield";

    /// <summary>
    /// Transactional store used for tenant/control/campaign state while
    /// ClickHouse receives append-oriented analytics. Use PostgreSQL for a
    /// production Central; SQLite is retained for single-node labs.
    /// </summary>
    public string ControlProvider { get; set; } = "Sqlite";

    /// <summary>Keep the control-plane fallback alive if analytics writes fail.</summary>
    public bool FailWrites { get; set; }
}
