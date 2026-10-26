namespace TraceMe.Engine;

public record HopStats(int Sent, int Recv, double? Min, double? Max, double? Avg, double? Last, double? Jitter, double? Stdev, double LossPct);

/// <summary>Streaming accumulator used for both live session stats and database windows, so the two always agree.</summary>
public sealed class Acc
{
    public int Sent, Recv;
    double _sum, _sumSq, _min = double.MaxValue, _max, _jit;
    double? _last, _prev;

    public void Add(double? rtt)
    {
        Sent++;
        if (rtt is double v)
        {
            Recv++; _sum += v; _sumSq += v * v;
            if (v < _min) _min = v;
            if (v > _max) _max = v;
            _last = v;
            if (_prev is double p) _jit += (Math.Abs(v - p) - _jit) / 16; // RFC 3550 interarrival jitter
            _prev = v;
        }
        else _last = null;
    }

    public void Reset() { Sent = Recv = 0; _sum = _sumSq = _max = _jit = 0; _min = double.MaxValue; _last = _prev = null; }

    public HopStats ToStats()
    {
        double? avg = Recv == 0 ? null : _sum / Recv;
        double? sd = Recv < 2 ? null : Math.Sqrt(Math.Max(0, _sumSq / Recv - avg!.Value * avg.Value));
        return new HopStats(Sent, Recv, Recv == 0 ? null : _min, Recv == 0 ? null : _max, avg, _last,
            Recv < 2 ? null : _jit, sd, Sent == 0 ? 0 : 100.0 * (Sent - Recv) / Sent);
    }
}

public static class Mos
{
    /// <summary>E-model style estimate: effective latency → R-factor → MOS (1.0 – 4.5).</summary>
    public static double Compute(double avgMs, double jitterMs, double lossPct)
    {
        var eff = avgMs + jitterMs * 2 + 10;
        var r = eff < 160 ? 93.2 - eff / 40 : 93.2 - (eff - 120) / 10;
        r = Math.Max(r - lossPct * 2.5, 0);
        return Math.Round(1 + 0.035 * r + 0.000007 * r * (r - 60) * (100 - r), 2);
    }
}

/// <summary>Metric calculations over a window of samples (NaN = lost probe), used by the alert engine.</summary>
public static class Metrics
{
    public static double? Avg(ReadOnlySpan<float> v)
    {
        double s = 0; int n = 0;
        foreach (var x in v) if (!float.IsNaN(x)) { s += x; n++; }
        return n == 0 ? null : s / n;
    }

    public static double? Max(ReadOnlySpan<float> v)
    {
        double m = double.NaN;
        foreach (var x in v) if (!float.IsNaN(x) && (double.IsNaN(m) || x > m)) m = x;
        return double.IsNaN(m) ? null : m;
    }

    public static double? Last(ReadOnlySpan<float> v) => v.Length == 0 || float.IsNaN(v[^1]) ? null : v[^1];

    /// <summary>Mean absolute difference between consecutive received samples.</summary>
    public static double? Jitter(ReadOnlySpan<float> v)
    {
        double s = 0; int n = 0; float? prev = null;
        foreach (var x in v)
        {
            if (float.IsNaN(x)) continue;
            if (prev is float p) { s += Math.Abs(x - p); n++; }
            prev = x;
        }
        return n == 0 ? null : s / n;
    }

    public static double LossPct(ReadOnlySpan<float> v)
    {
        if (v.Length == 0) return 0;
        int lost = 0;
        foreach (var x in v) if (float.IsNaN(x)) lost++;
        return 100.0 * lost / v.Length;
    }

    public static bool AllLost(ReadOnlySpan<float> v)
    {
        if (v.Length == 0) return false;
        foreach (var x in v) if (!float.IsNaN(x)) return false;
        return true;
    }
}
