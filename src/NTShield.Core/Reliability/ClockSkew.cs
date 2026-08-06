namespace NTShield.Core.Reliability;

public static class ClockSkew
{
    /// <summary>
    /// Reports agent clock skew relative to server UTC.
    /// Positive = agent ahead of server.
    /// </summary>
    public static TimeSpan Compute(DateTimeOffset agentUtc, DateTimeOffset serverUtc) =>
        agentUtc - serverUtc;

    public static bool IsSignificant(TimeSpan skew, TimeSpan? threshold = null) =>
        Math.Abs(skew.TotalSeconds) >= (threshold ?? TimeSpan.FromMinutes(2)).TotalSeconds;
}
