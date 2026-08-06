namespace NTShield.Core.Reliability;

public sealed class ExponentialBackoff
{
    private readonly TimeSpan _initial;
    private readonly TimeSpan _max;
    private int _attempt;

    public ExponentialBackoff(TimeSpan? initial = null, TimeSpan? max = null)
    {
        _initial = initial ?? TimeSpan.FromSeconds(2);
        _max = max ?? TimeSpan.FromMinutes(5);
    }

    public int Attempt => _attempt;

    public void Reset() => _attempt = 0;

    public TimeSpan NextDelay()
    {
        _attempt++;
        // 2^n with cap; attempt 1 => initial
        var ms = _initial.TotalMilliseconds * Math.Pow(2, Math.Min(_attempt - 1, 10));
        ms = Math.Min(ms, _max.TotalMilliseconds);
        // full jitter
        var jitter = Random.Shared.NextDouble() * 0.2 + 0.9;
        return TimeSpan.FromMilliseconds(ms * jitter);
    }
}
