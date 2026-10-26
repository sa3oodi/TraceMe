using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using TraceMe.Engine;
using TraceMe.Models;

namespace TraceMe.Alerts;

public sealed record AlertContext(AlertRule Rule, string TargetId, string Target, string Host, int Hop, string HopHost,
    string Metric, double Value, double Threshold, string State, string Message, DateTimeOffset Time);

public sealed class AlertEngine
{
    sealed class State
    {
        public bool Active; public int Consec; public DateTime Since, LastFired;
        public string RuleName = "", TargetId = "", HopHost = ""; public int Hop; public double Value;
    }

    readonly Hub _hub;
    readonly ConcurrentDictionary<string, State> _states = new();

    public AlertEngine(Hub hub) => _hub = hub;

    public static bool Compare(double v, string op, double thr) => op == "<" ? v < thr : v > thr;

    /// <summary>Metric over the most recent samples of a hop. Returns null when there is not enough data to judge.</summary>
    public static (bool? cond, double value) Check(AlertRule rule, float[] vals, bool routeChanged)
    {
        switch (rule.Metric)
        {
            case "routechange": return (routeChanged, routeChanged ? 1 : 0);
            case "noresponse":
                return vals.Length < rule.Samples ? (null, 0) : (Metrics.AllLost(vals), rule.Samples);
        }
        if (vals.Length < rule.Samples) return (null, 0);
        double? v = rule.Metric switch
        {
            "avg" => Metrics.Avg(vals),
            "max" => Metrics.Max(vals),
            "last" => Metrics.Last(vals),
            "jitter" => Metrics.Jitter(vals),
            "loss" => Metrics.LossPct(vals),
            "mos" => Metrics.Avg(vals) is double a ? Mos.Compute(a, Metrics.Jitter(vals) ?? 0, Metrics.LossPct(vals)) : null,
            _ => null
        };
        if (v is not double d) return (false, 0); // no replies at all: latency is undefined, loss/no-response rules cover it
        return (Compare(d, rule.Op, rule.Value), d);
    }

    public void Evaluate(TargetRunner r, IReadOnlyList<RouteChange> changes)
    {
        var rules = _hub.Settings.Alerts;
        var live = rules.Where(x => x.Enabled).Select(x => x.Id).ToHashSet();
        foreach (var k in _states.Keys.ToList())
            if (!live.Contains(k.Split('|')[0])) _states.TryRemove(k, out _);

        foreach (var rule in rules)
        {
            if (!rule.Enabled || (rule.TargetId != null && rule.TargetId != r.Id)) continue;
            IEnumerable<HopLive> hops = rule.Scope switch
            {
                "destination" => new[] { r.DestinationHop() }.OfType<HopLive>(),
                "hop" => new[] { r.GetHop(rule.Hop) }.OfType<HopLive>(),
                _ => r.VisibleHops()
            };
            bool isDestScope = rule.Scope == "destination";
            foreach (var hop in hops)
            {
                bool rc = changes.Any(c => c.Hop == hop.Hop);
                var (cond, value) = Check(rule, hop.Tail(rule.Samples), rc);
                var key = $"{rule.Id}|{r.Id}|{hop.Hop}";
                var st = _states.GetOrAdd(key, _ => new State());
                st.RuleName = rule.Name; st.TargetId = r.Id; st.Hop = hop.Hop; st.Value = value;
                var now = DateTime.UtcNow;
                if (rule.Metric == "routechange")
                {
                    if (cond == true && now - st.LastFired > TimeSpan.FromSeconds(30)) { st.LastFired = now; Fire(rule, r, hop, value, "triggered"); }
                    continue;
                }
                if (cond == true)
                {
                    st.Consec++;
                    if (!st.Active && st.Consec >= rule.ConsecutiveRounds)
                    {
                        st.Active = true; st.Since = now; st.LastFired = now;
                        Fire(rule, r, hop, value, "triggered");
                    }
                    else if (st.Active && rule.RepeatMinutes > 0 && now - st.LastFired >= TimeSpan.FromMinutes(rule.RepeatMinutes))
                    {
                        st.LastFired = now;
                        Fire(rule, r, hop, value, "still active");
                    }
                }
                else if (cond == false)
                {
                    st.Consec = 0;
                    if (st.Active)
                    {
                        st.Active = false;
                        if (rule.NotifyOnClear) Fire(rule, r, hop, value, "cleared");
                    }
                }
            }
        }
    }

    public static string MetricLabel(string m) => m switch
    {
        "avg" => "avg latency", "max" => "max latency", "last" => "latency", "jitter" => "jitter", "loss" => "packet loss",
        "noresponse" => "consecutive lost probes", "mos" => "MOS", "routechange" => "route change", _ => m
    };

    void Fire(AlertRule rule, TargetRunner r, HopLive hop, double value, string state)
    {
        var addr = hop.Address;
        var hopHost = addr == null ? "no response" : (_hub.Dns.TryGet(addr, false) ?? addr);
        var unit = rule.Metric is "avg" or "max" or "last" or "jitter" ? " ms" : rule.Metric == "loss" ? " %" : "";
        string detail = rule.Metric == "routechange"
            ? "route changed"
            : rule.Metric == "noresponse"
                ? $"no response for {rule.Samples} probes"
                : $"{MetricLabel(rule.Metric)} {value.ToString("0.##", CultureInfo.InvariantCulture)}{unit} ({rule.Op} {rule.Value.ToString("0.##", CultureInfo.InvariantCulture)}{unit}, last {rule.Samples})";
        var msg = $"{rule.Name}: {r.Config.DisplayName} hop {hop.Hop} ({hopHost}) — {detail} [{state}]";
        var ctx = new AlertContext(rule, r.Id, r.Config.DisplayName, r.Config.Host, hop.Hop, hopHost, rule.Metric, value, rule.Value, state, msg, DateTimeOffset.UtcNow);
        bool cleared = state == "cleared";
        var sound = !cleared ? rule.Actions.FirstOrDefault(a => a.Type == "sound") : null;
        _hub.Bus.Publish(r.Id, "alert", cleared ? "info" : "warn", msg,
            JsonSerializer.Serialize(new { ruleId = rule.Id, hop = hop.Hop, metric = rule.Metric, value, state }),
            sound == null ? null : (sound.Sound ?? "sonar"), toast: rule.Actions.Any(a => a.Type == "toast"));
        foreach (var a in rule.Actions.Where(a => a.Type is "email" or "webhook" or "exec" or "script"))
        {
            var action = a;
            _ = Task.Run(async () =>
            {
                try { await AlertActions.RunAsync(_hub, ctx, action); }
                catch (Exception e)
                {
                    _hub.Bus.Publish(r.Id, "error", "warn", $"Alert action '{action.Type}' for '{rule.Name}' failed: {e.Message}", toast: false);
                }
            });
        }
    }

    public object[] ActiveFor(string tid) => _states
        .Where(kv => kv.Value.Active && kv.Value.TargetId == tid)
        .Select(kv => (object)new { rule = kv.Value.RuleName, ruleId = kv.Key.Split('|')[0], hop = kv.Value.Hop, value = Math.Round(kv.Value.Value, 2), since = new DateTimeOffset(kv.Value.Since, TimeSpan.Zero).ToUnixTimeMilliseconds() })
        .ToArray();

    public void Forget(string tid)
    {
        foreach (var k in _states.Keys.Where(k => k.Split('|')[1] == tid).ToList()) _states.TryRemove(k, out _);
    }

    /// <summary>Fires a rule's actions with sample data so the user can verify email/webhook/script setups.</summary>
    public async Task TestAsync(AlertRule rule)
    {
        var ctx = new AlertContext(rule, "test", "Test target", "example.com", 5, "router.example.net", rule.Metric, rule.Value + 1, rule.Value,
            "test", $"{rule.Name}: test notification from TraceMe", DateTimeOffset.UtcNow);
        _hub.Bus.Publish(null, "alert", "info", ctx.Message, null,
            rule.Actions.FirstOrDefault(a => a.Type == "sound") is { } s ? (s.Sound ?? "sonar") : null, toast: true);
        foreach (var a in rule.Actions.Where(a => a.Type is "email" or "webhook" or "exec" or "script"))
            await AlertActions.RunAsync(_hub, ctx, a);
    }
}
