namespace NTShield.Shared.Enums;

/// <summary>
/// Mirrors Windows MIB_TCP_STATE values (iphlpapi).
/// </summary>
public enum TcpConnectionState
{
    Closed = 1,
    Listen = 2,
    SynSent = 3,
    SynRcvd = 4,
    Established = 5,
    FinWait1 = 6,
    FinWait2 = 7,
    CloseWait = 8,
    Closing = 9,
    LastAck = 10,
    TimeWait = 11,
    DeleteTcb = 12
}
