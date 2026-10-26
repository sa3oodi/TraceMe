using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using TraceMe.Models;
using TraceMe.Services;

namespace TraceMe.Engine;

/// <summary>Live state of one hop: session statistics plus a ring buffer of the most recent samples.</summary>
public sealed class HopLive
{
    public const int Ring = 900;
    readonly object _g = new();
    readonly Acc _acc = new();
    readonly float[] _vals = new float[Ring];
    readonly HashSet<string> _seen = new();
    readonly Dictionary<string, DateTime> _lastSeen = new();
    int _head, _count;
    string? _addr, _detail;

    public HopLive(int hop) => Hop = hop;
    public int Hop { get; }

    public string? Address { get { lock (_g) return _addr; } }
    public int Recv { get { lock (_g) return _acc.Recv; } }
    public int Sent { get { lock (_g) return _acc.Sent; } }

    /// <summary>Records a sample. Returns true when the responding address is new to this hop (not seen in the last 10 minutes), i.e. a genuine path change rather than load balancing between known routers.</summary>
    public bool Add(double? rtt, string? addr, string? detail)
    {
        lock (_g)
        {
            bool novel = false;
            _acc.Add(rtt);
            if (addr != null)
            {
                var now = DateTime.UtcNow;
                novel = !_lastSeen.TryGetValue(addr, out var t) || now - t > TimeSpan.FromMinutes(10);
                _lastSeen[addr] = now; _addr = addr; _seen.Add(addr);
            }
            if (detail != null) _detail = detail;
            _vals[_head] = rtt is double r ? (float)r : float.NaN;
            _head = (_head + 1) % Ring;
            if (_count < Ring) _count++;
            return novel;
        }
    }

    public (HopStats stats, string? addr, string[] seen, string? detail) Read()
    {
        lock (_g) return (_acc.ToStats(), _addr, _seen.ToArray(), _detail);
    }

    /// <summary>Most recent <paramref name="n"/> samples in chronological order; NaN marks a lost probe.</summary>
    public float[] Tail(int n)
    {
        lock (_g)
        {
            n = Math.Min(n, _count);
            var res = new float[n];
            for (int i = 0; i < n; i++) res[i] = _vals[((_head - n + i) % Ring + Ring) % Ring];
            return res;
        }
    }
}

public sealed record RouteChange(int Hop, string? From, string To);

public sealed class TargetRunner
{
    readonly Hub _hub;
    readonly CancellationTokenSource _cts = new();
    readonly SemaphoreSlim _wake = new(0);
    readonly Dictionary<int, HopLive> _hops = new();
    volatile TaskCompletionSource _tick = new(TaskCreationOptions.RunContinuationsAsynchronously);
    volatile TargetConfig _cfg;
    IPAddress? _dest, _source;
    DateTime _lastResolve = DateTime.MinValue, _lastRouteEvent = DateTime.MinValue, _lastErrorEvent = DateTime.MinValue;
    string? _lastErrorText, _error;
    int _destMiss, _runRounds;
    DateTime _runStart = DateTime.UtcNow;
    bool _autoStopped;
    Task? _loop;

    public TargetRunner(Hub hub, TargetConfig cfg) { _hub = hub; _cfg = cfg; }

    public string Id => _cfg.Id;
    public TargetConfig Config => _cfg;
    public IPAddress? Dest => _dest;
    public IPAddress? Source => _source;
    public long Round { get; private set; }
    public int? DestHop { get; private set; }
    public DateTimeOffset SessionStart { get; private set; } = DateTimeOffset.UtcNow;
    public string Status => _cfg.Paused ? (_autoStopped ? "stopped" : "paused") : _error != null ? "error" : Round == 0 ? "starting" : "running";
    public string? Error => _error;

    public void Start() => _loop = Task.Run(() => Loop(_cts.Token));

    public async Task StopAsync()
    {
        _cts.Cancel(); Notify();
        if (_loop != null) { try { await _loop.WaitAsync(TimeSpan.FromSeconds(5)); } catch { } }
    }

    public void Pause(bool paused)
    {
        _cfg.Paused = paused; _autoStopped = false;
        if (!paused) { _runRounds = 0; _runStart = DateTime.UtcNow; _error = null; }
        _wake.Release();
        Notify();
    }

    public void TraceNow() => _wake.Release();

    public void Reset()
    {
        lock (_hops) _hops.Clear();
        SessionStart = DateTimeOffset.UtcNow;
        Notify();
    }

    /// <summary>Applies edited settings. Changes that make existing statistics meaningless start a fresh session.</summary>
    public void Apply(TargetConfig n)
    {
        var o = _cfg;
        bool path = o.Host != n.Host || o.Method != n.Method || o.EffectivePort != n.EffectivePort || o.AgentUrl != n.AgentUrl
            || o.PreferIPv6 != n.PreferIPv6 || o.SourceAddress != n.SourceAddress || o.StartHop != n.StartHop;
        n.Paused = o.Paused;
        _cfg = n;
        if (path)
        {
            _dest = null; _lastResolve = DateTime.MinValue; DestHop = null; _destMiss = 0; _error = null;
            Reset();
        }
        _wake.Release();
        Notify();
    }

    void Notify() => Interlocked.Exchange(ref _tick, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).TrySetResult();

    public async Task WaitForUpdateAsync(CancellationToken ct)
    {
        var t = _tick.Task;
        await t.WaitAsync(ct);
    }

    public IReadOnlyList<HopLive> HopsList() { lock (_hops) return _hops.Values.OrderBy(h => h.Hop).ToList(); }
    public HopLive? GetHop(int hop) { lock (_hops) return _hops.TryGetValue(hop, out var h) ? h : null; }

    /// <summary>Hops worth showing: everything up to the destination, or — while it is unreachable — a little past the last responder.</summary>
    public IReadOnlyList<HopLive> VisibleHops()
    {
        var all = HopsList();
        int limit;
        if (DestHop is int d) limit = d;
        else
        {
            int maxResp = all.Where(h => h.Recv > 0).Select(h => h.Hop).DefaultIfEmpty(0).Max();
            limit = Math.Min(_cfg.MaxHops, Math.Max(3, maxResp + 2));
        }
        return all.Where(h => h.Hop <= limit).ToList();
    }

    /// <summary>The hop that represents the destination for alerts and summaries.</summary>
    public HopLive? DestinationHop()
    {
        if (DestHop is int d) return GetHop(d);
        return HopsList().LastOrDefault(h => h.Recv > 0);
    }

    // ------------------------------------------------------------------ loop

    async Task Loop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var sw = Stopwatch.StartNew();
            int wait;
            try
            {
                var cfg = _cfg;
                if (!cfg.Paused && StopConditionMet(cfg))
                {
                    cfg.Paused = true; _autoStopped = true;
                    _hub.Targets.Persist(this);
                    _hub.Bus.Publish(cfg.Id, "info", "info", $"{cfg.DisplayName}: tracing stopped (auto-stop condition reached).", toast: true);
                    Notify();
                }
                if (!_cfg.Paused) await RunRoundAsync(ct);
                wait = _cfg.Paused ? 1000 : _error != null ? 3000 : (int)Math.Max(50, _cfg.IntervalMs - sw.ElapsedMilliseconds);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e) { SetError(e.Message); wait = 3000; }
            try { await _wake.WaitAsync(wait, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    bool StopConditionMet(TargetConfig c) =>
        (c.StopAfterRounds is int n && _runRounds >= n) ||
        (c.StopAfterMinutes is int m && (DateTime.UtcNow - _runStart).TotalMinutes >= m);

    void SetError(string msg)
    {
        if (_error != msg) { _error = msg; Notify(); }
        if (msg != _lastErrorText || DateTime.UtcNow - _lastErrorEvent > TimeSpan.FromMinutes(5))
        {
            _lastErrorText = msg; _lastErrorEvent = DateTime.UtcNow;
            _hub.Bus.Publish(Id, "error", "warn", $"{_cfg.DisplayName}: {msg}", toast: false);
        }
    }

    async Task<bool> EnsureResolvedAsync(TargetConfig cfg, CancellationToken ct)
    {
        if (_dest != null && DateTime.UtcNow - _lastResolve < TimeSpan.FromMinutes(5)) return true;
        if (cfg.AgentUrl != null && _dest == null && DateTime.UtcNow - _lastResolve < TimeSpan.FromMinutes(1) && _lastResolve != DateTime.MinValue) return true;
        try
        {
            IPAddress ip;
            if (IPAddress.TryParse(cfg.Host, out var lit)) ip = lit;
            else
            {
                var all = await Dns.GetHostAddressesAsync(cfg.Host, ct);
                var want = cfg.PreferIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
                ip = all.FirstOrDefault(a => a.AddressFamily == want) ?? all.FirstOrDefault()
                    ?? throw new SocketException((int)SocketError.HostNotFound);
            }
            if (_dest != null && !_dest.Equals(ip))
            {
                _hub.Bus.Publish(Id, "info", "info", $"{cfg.DisplayName}: address changed from {_dest} to {ip}; statistics restarted.", toast: false);
                lock (_hops) _hops.Clear();
                DestHop = null;
                SessionStart = DateTimeOffset.UtcNow;
            }
            _dest = ip;
            _source = DetectSource(ip, cfg.SourceAddress);
            _lastResolve = DateTime.UtcNow;
            if (_error != null) { _error = null; Notify(); }
            return true;
        }
        catch (Exception e) when (e is SocketException or ArgumentException)
        {
            _lastResolve = DateTime.UtcNow;
            if (cfg.AgentUrl != null) { _dest = null; return true; } // the agent resolves the name itself
            SetError($"cannot resolve '{cfg.Host}'");
            return false;
        }
    }

    public static IPAddress? DetectSource(IPAddress dest, string? configured)
    {
        if (configured != null && IPAddress.TryParse(configured, out var cfgIp)) return cfgIp;
        try
        {
            using var s = new Socket(dest.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            s.Connect(dest, 9); // no packet is sent; the OS just selects the outgoing interface
            var a = ((IPEndPoint)s.LocalEndPoint!).Address;
            return a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any) ? null : new IPAddress(a.GetAddressBytes());
        }
        catch { return null; }
    }

    async Task RunRoundAsync(CancellationToken ct)
    {
        var cfg = _cfg;
        if (!await EnsureResolvedAsync(cfg, ct)) return;
        int from = cfg.StartHop;
        int to = Math.Max(from, Math.Min(cfg.MaxHops, DestHop ?? cfg.MaxHops));
        var ctx = new ProbeContext(_dest, cfg.Host, _source, cfg, _hub.Pool);
        long t0 = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        ProbeResult[] res;
        try { res = await ProberFactory.For(cfg).RunRoundAsync(ctx, from, to, ct); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            SetError("agent request timed out"); return;
        }
        catch (Exception e) when (e is HttpRequestException or InvalidOperationException)
        {
            SetError(e.Message); return;
        }
        if (_error != null) { _error = null; Notify(); }
        ApplyResults(t0, res, cfg);
    }

    void ApplyResults(long t0, ProbeResult[] res, TargetConfig cfg)
    {
        int reachedAt = res.Where(r => r.Kind == ProbeKind.Reached).Select(r => r.Ttl).DefaultIfEmpty(0).Min();
        if (reachedAt > 0)
        {
            if (DestHop != reachedAt)
            {
                DestHop = reachedAt;
                lock (_hops) foreach (var k in _hops.Keys.Where(k => k > reachedAt).ToList()) _hops.Remove(k);
            }
            _destMiss = 0;
        }
        else if (DestHop is int d && ++_destMiss >= 5) { DestHop = null; _destMiss = 0; } // lost for 5 rounds: rediscover the path length

        int last = reachedAt > 0 ? reachedAt : (DestHop ?? res.Select(r => r.Ttl).DefaultIfEmpty(0).Max());
        var changes = new List<RouteChange>();
        foreach (var r in res.OrderBy(r => r.Ttl))
        {
            if (r.Ttl > last) continue;
            HopLive h;
            lock (_hops) { if (!_hops.TryGetValue(r.Ttl, out h!)) _hops[r.Ttl] = h = new HopLive(r.Ttl); }
            double? rtt = r.Kind is ProbeKind.Timeout or ProbeKind.Error ? null : r.Rtt;
            var prev = h.Address;
            bool novel = h.Add(rtt, rtt == null ? null : r.Addr, r.Detail);
            _hub.Db.AddSample(Id, t0, r.Ttl, rtt);
            if (rtt != null && r.Addr != null)
            {
                if (prev != r.Addr) _hub.Db.AddRoute(Id, t0, r.Ttl, r.Addr);
                if (prev != null && prev != r.Addr && novel) changes.Add(new RouteChange(r.Ttl, prev, r.Addr)); // load balancing between known routers is not a route change
                _hub.Dns.TryGet(r.Addr, cfg.ResolveNames);
                if (_hub.Settings.Current.AsnLookup) _hub.Asn.TryGet(r.Addr, true);
            }
        }
        Round++; _runRounds++;
        if (changes.Count > 0 && DateTime.UtcNow - _lastRouteEvent > TimeSpan.FromSeconds(10))
        {
            _lastRouteEvent = DateTime.UtcNow;
            var msg = string.Join("; ", changes.Take(4).Select(c => $"hop {c.Hop}: {c.From} → {c.To}")) + (changes.Count > 4 ? $" (+{changes.Count - 4} more)" : "");
            _hub.Bus.Publish(Id, "route", "warn", $"{cfg.DisplayName}: route change — {msg}", toast: false);
        }
        try { _hub.Alerts.Evaluate(this, changes); }
        catch (Exception e) { Console.Error.WriteLine("[alerts] " + e); }
        Notify();
    }

    // ------------------------------------------------------------------ snapshots

    public double? Mos()
    {
        var h = DestinationHop();
        if (h == null) return null;
        var (s, _, _, _) = h.Read();
        return s.Recv >= 2 && s.Avg is double a && s.Jitter is double j ? Engine.Mos.Compute(a, j, s.LossPct) : null;
    }

    public TargetConfig MaskedConfig()
    {
        var c = _cfg.Clone();
        if (!string.IsNullOrEmpty(c.AgentToken)) c.AgentToken = "••••••";
        return c;
    }

    string? Warning()
    {
        var cfg = _cfg;
        if (cfg.AgentUrl != null || cfg.Method == "icmp") return null;
        if (_source == null) return null;
        if (_hub.Pool.Get(_source) != null) return null;
        return (_hub.Pool.LastError(_source) ?? "Raw ICMP capture unavailable") +
            " Only the destination can be detected; intermediate hops will show no response.";
    }

    static double? N(double? v) => v is double d && double.IsFinite(d) ? Math.Round(d, 3) : null;

    public object HopSnapshot(HopLive h, int tail, GlobalSettings gs, TargetConfig cfg)
    {
        var (s, addr, seen, detail) = h.Read();
        var series = h.Tail(tail).Select(v => float.IsNaN(v) ? (double?)null : Math.Round(v, 2)).ToArray();
        return HopView(h.Hop, s, addr, seen, detail, series, gs, cfg);
    }

    /// <summary>Shared presentation of one hop for live snapshots and database windows.</summary>
    public object HopView(int hop, HopStats s, string? addr, string[] seen, string? detail, double?[]? series, GlobalSettings gs, TargetConfig cfg)
    {
        string? name = null; AsnInfo? asn = null;
        if (addr != null)
        {
            if (gs.Aliases.TryGetValue(addr, out var al)) name = al;
            else name = _hub.Dns.TryGet(addr, cfg.ResolveNames);
            if (gs.AsnLookup) asn = _hub.Asn.TryGet(addr, true);
            else if (IPAddress.TryParse(addr, out var ipa) && AsnService.IsPrivate(ipa)) asn = _hub.Asn.TryGet(addr, false);
        }
        return new
        {
            hop, address = addr, name, asn, sent = s.Sent, recv = s.Recv, lossPct = Math.Round(s.LossPct, 2),
            last = N(s.Last), min = N(s.Min), max = N(s.Max), avg = N(s.Avg), jitter = N(s.Jitter), stdev = N(s.Stdev),
            addresses = seen, routeChanged = seen.Length > 1, detail, series,
            custom = _hub.Columns.Evaluate(hop, s, addr, name, gs)
        };
    }

    public object Snapshot(int tail = 240)
    {
        var cfg = _cfg; var gs = _hub.Settings.Current;
        var hops = VisibleHops();
        return new
        {
            id = Id, host = cfg.Host, name = cfg.Name, displayName = cfg.DisplayName, group = cfg.Group, method = cfg.Method,
            agent = cfg.AgentUrl != null, address = _dest?.ToString(), source = _source?.ToString(),
            status = Status, error = _error, warning = Warning(), round = Round, paused = cfg.Paused,
            destHop = DestHop, sessionStart = SessionStart.ToUnixTimeMilliseconds(), mos = Mos(),
            config = MaskedConfig(), alerts = _hub.Alerts.ActiveFor(Id),
            hops = hops.Select(h => HopSnapshot(h, tail, gs, cfg)).ToArray()
        };
    }

    /// <summary>Compact form for the summary screen.</summary>
    public object Summary()
    {
        var cfg = _cfg;
        var dest = DestinationHop();
        HopStats? s = null; string? addr = null; float[] spark = Array.Empty<float>();
        if (dest != null) { var r = dest.Read(); s = r.stats; addr = r.addr; spark = dest.Tail(90); }
        return new
        {
            id = Id, host = cfg.Host, name = cfg.Name, displayName = cfg.DisplayName, group = cfg.Group, method = cfg.Method,
            appKey = cfg.AppKey, auto = cfg.Auto,
            agent = cfg.AgentUrl != null, address = _dest?.ToString(), status = Status, error = _error, warning = Warning(),
            round = Round, destHop = DestHop, hopCount = VisibleHops().Count, mos = Mos(), intervalMs = cfg.IntervalMs,
            avg = N(s?.Avg), last = N(s?.Last), min = N(s?.Min), max = N(s?.Max), jitter = N(s?.Jitter),
            lossPct = s == null ? (double?)null : Math.Round(s.LossPct, 2), destAddress = addr,
            alerts = _hub.Alerts.ActiveFor(Id),
            series = spark.Select(v => float.IsNaN(v) ? (double?)null : Math.Round(v, 2)).ToArray()
        };
    }
}
