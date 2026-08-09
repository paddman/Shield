using System.Collections.Concurrent;

namespace NTShield.Server.Security;

public sealed class DashboardLoginAttemptLimiter
{
    private sealed record AttemptWindow(DateTimeOffset StartedAtUtc, int Failures, DateTimeOffset LockedUntilUtc);

    private readonly ConcurrentDictionary<string, AttemptWindow> _attempts = new(StringComparer.Ordinal);

    public bool IsAllowed(string key, DateTimeOffset now, out TimeSpan retryAfter)
    {
        retryAfter = TimeSpan.Zero;
        if (!_attempts.TryGetValue(key, out var current)) return true;
        if (current.LockedUntilUtc <= now)
        {
            if (now - current.StartedAtUtc > TimeSpan.FromMinutes(10)) _attempts.TryRemove(key, out _);
            return true;
        }

        retryAfter = current.LockedUntilUtc - now;
        return false;
    }

    public void RecordFailure(string key, DateTimeOffset now)
    {
        _attempts.AddOrUpdate(
            key,
            _ => new AttemptWindow(now, 1, DateTimeOffset.MinValue),
            (_, current) =>
            {
                var failures = now - current.StartedAtUtc > TimeSpan.FromMinutes(10)
                    ? 1
                    : current.Failures + 1;
                var started = failures == 1 ? now : current.StartedAtUtc;
                var lockSeconds = failures < 5 ? 0 : Math.Min(300, 5 * (1 << Math.Min(6, failures - 5)));
                return new AttemptWindow(started, failures, now.AddSeconds(lockSeconds));
            });
    }

    public void RecordSuccess(string key) => _attempts.TryRemove(key, out _);
}
